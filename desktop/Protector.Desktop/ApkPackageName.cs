using System.IO;
using System.IO.Compression;
using System.Text;

namespace Protector.Desktop;

/// <summary>
/// Reads applicationId / manifest package from an APK without requiring aapt.
/// </summary>
internal static class ApkPackageName
{
    private const int ResXmlType = 0x0003;
    private const int ResStringPoolType = 0x0001;
    private const int ResXmlStartElementType = 0x0102;
    private const int ResXmlResourceMapType = 0x0180;

    /// <summary>Return manifest package name, or null if unavailable.</summary>
    public static string? TryRead(string apkPath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(apkPath) || !File.Exists(apkPath))
                return null;

            using var zip = ZipFile.OpenRead(apkPath);
            var entry = zip.GetEntry("AndroidManifest.xml");
            if (entry == null)
                return null;

            using var stream = entry.Open();
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            return ParsePackageFromAxml(ms.ToArray());
        }
        catch
        {
            return null;
        }
    }

    private static string? ParsePackageFromAxml(byte[] data)
    {
        if (data.Length < 8)
            return null;

        // Some builds wrap with plain XML (rare); handle quickly.
        if (data[0] == (byte)'<' || (data[0] == 0xEF && data.Length > 2))
        {
            var text = Encoding.UTF8.GetString(data);
            var m = System.Text.RegularExpressions.Regex.Match(
                text, @"package\s*=\s*""([^""]+)""", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : null;
        }

        int fileType = ReadU16(data, 0);
        // Standard: type=0x0003 (RES_XML), headerSize=8, then chunks.
        // Older: sometimes starts directly with string pool.
        int pos = 0;
        if (fileType == ResXmlType)
            pos = ReadU16(data, 2); // header size
        else if (fileType == ResStringPoolType)
            pos = 0;
        else
            return null;

        string[]? strings = null;
        while (pos + 8 <= data.Length)
        {
            int chunkType = ReadU16(data, pos);
            int headerSize = ReadU16(data, pos + 2);
            int chunkSize = ReadU32(data, pos + 4);
            if (chunkSize < 8 || pos + chunkSize > data.Length)
                break;

            if (chunkType == ResStringPoolType)
            {
                strings = ReadStringPool(data, pos);
            }
            else if (chunkType == ResXmlStartElementType && strings != null)
            {
                // After chunk header: lineNumber(4) comment(4) ns(4) name(4) attrStart(2) attrSize(2) attrCount(2) idIndex(2) classIndex(2) styleIndex(2)
                int baseOff = pos + headerSize;
                if (baseOff + 20 > pos + chunkSize)
                {
                    pos += chunkSize;
                    continue;
                }

                int nameIdx = ReadU32(data, baseOff + 4); // ns at 0, name at 4 relative to node after line/comment... 
                // Structure of RES_XML_TREE_NODE: lineNumber, comment, then START_ELEMENT extends with ns, name, ...
                // headerSize typically 16 for node start → line(4)+comment(4) already in header, then ns+name at headerSize.
                int nsIdx = ReadS32(data, pos + headerSize);
                int elNameIdx = ReadS32(data, pos + headerSize + 4);
                int attrStart = ReadU16(data, pos + headerSize + 8);
                int attrSize = ReadU16(data, pos + headerSize + 10);
                int attrCount = ReadU16(data, pos + headerSize + 12);
                _ = nsIdx;
                _ = nameIdx;

                string? elName = GetString(strings, elNameIdx);
                if (string.Equals(elName, "manifest", StringComparison.Ordinal))
                {
                    int attrBase = pos + headerSize + attrStart;
                    for (int i = 0; i < attrCount; i++)
                    {
                        int a = attrBase + i * (attrSize > 0 ? attrSize : 20);
                        if (a + 20 > pos + chunkSize)
                            break;
                        int attrNameIdx = ReadS32(data, a + 4);
                        int rawValueIdx = ReadS32(data, a + 8);
                        // typed value at a+12: size(2) res0(1) dataType(1) data(4)
                        int dataType = data[a + 15];
                        int dataVal = ReadU32(data, a + 16);
                        string? attrName = GetString(strings, attrNameIdx);
                        if (!string.Equals(attrName, "package", StringComparison.Ordinal))
                            continue;

                        // TYPE_STRING = 0x03
                        if (dataType == 0x03)
                        {
                            var pkg = GetString(strings, dataVal);
                            if (!string.IsNullOrWhiteSpace(pkg))
                                return pkg;
                        }

                        var raw = GetString(strings, rawValueIdx);
                        if (!string.IsNullOrWhiteSpace(raw))
                            return raw;
                    }
                }
            }
            else if (chunkType == ResXmlResourceMapType)
            {
                // skip
            }

            pos += chunkSize;
            // Align? chunkSize already includes padding typically.
        }

        return null;
    }

    private static string[]? ReadStringPool(byte[] data, int poolPos)
    {
        int headerSize = ReadU16(data, poolPos + 2);
        int chunkSize = ReadU32(data, poolPos + 4);
        int stringCount = ReadU32(data, poolPos + 8);
        // int styleCount = ReadU32(data, poolPos + 12);
        int flags = ReadU32(data, poolPos + 16);
        int stringsStart = ReadU32(data, poolPos + 20);
        // int stylesStart = ReadU32(data, poolPos + 24);
        bool utf8 = (flags & (1 << 8)) != 0;

        if (stringCount <= 0 || stringCount > 200_000)
            return null;

        int offsetsPos = poolPos + headerSize;
        var strings = new string[stringCount];
        int stringsBase = poolPos + stringsStart;

        for (int i = 0; i < stringCount; i++)
        {
            int off = ReadU32(data, offsetsPos + i * 4);
            int sp = stringsBase + off;
            if (sp < 0 || sp >= data.Length)
            {
                strings[i] = "";
                continue;
            }

            try
            {
                strings[i] = utf8 ? ReadUtf8String(data, sp) : ReadUtf16String(data, sp);
            }
            catch
            {
                strings[i] = "";
            }
        }

        _ = chunkSize;
        return strings;
    }

    private static string ReadUtf16String(byte[] data, int pos)
    {
        // charLen is uint16; if high bit set, uint32 length follows (rare)
        int charLen = ReadU16(data, pos);
        pos += 2;
        if ((charLen & 0x8000) != 0)
        {
            charLen = ((charLen & 0x7FFF) << 16) | ReadU16(data, pos);
            pos += 2;
        }

        if (charLen < 0 || pos + charLen * 2 > data.Length)
            return "";
        return Encoding.Unicode.GetString(data, pos, charLen * 2);
    }

    private static string ReadUtf8String(byte[] data, int pos)
    {
        // UTF-8 string pool: charLen (utf16 length) then byteLen, both possibly 2 bytes with high bit.
        int charLen = data[pos];
        pos++;
        if ((charLen & 0x80) != 0)
        {
            charLen = ((charLen & 0x7F) << 8) | data[pos];
            pos++;
        }

        int byteLen = data[pos];
        pos++;
        if ((byteLen & 0x80) != 0)
        {
            byteLen = ((byteLen & 0x7F) << 8) | data[pos];
            pos++;
        }

        _ = charLen;
        if (byteLen < 0 || pos + byteLen > data.Length)
            return "";
        return Encoding.UTF8.GetString(data, pos, byteLen);
    }

    private static string? GetString(string[] strings, int idx)
    {
        if (idx < 0 || idx >= strings.Length)
            return null;
        return strings[idx];
    }

    private static int ReadU16(byte[] d, int i) => d[i] | (d[i + 1] << 8);
    private static int ReadU32(byte[] d, int i) =>
        d[i] | (d[i + 1] << 8) | (d[i + 2] << 16) | (d[i + 3] << 24);
    private static int ReadS32(byte[] d, int i) => ReadU32(d, i);
}
