using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

internal static class Launcher
{
    // Replaced by the local builder after generating the payload manifest.
    const string ManifestSha256 = "__MANIFEST_SHA256__";

    static bool IsUserData(string relative) {
        string top=relative.Split('/')[0];
        if(top.Equals("app",StringComparison.OrdinalIgnoreCase)||top.Equals("runtime",StringComparison.OrdinalIgnoreCase)||top.Equals("licenses",StringComparison.OrdinalIgnoreCase))return false;
        if(Array.IndexOf(new[]{"id_rsa","id_ed25519","id_ecdsa","id_dsa","id_xmss"},Path.GetFileName(relative).ToLowerInvariant())>=0)return true;
        string extension=Path.GetExtension(relative).ToLowerInvariant();
        return Array.IndexOf(new[]{".okv",".okvr",".lock",".pem",".key",".der",".pub",".jwk",".p12",".pfx",".jks",".ppk",".asc",".pgp",".gpg",".crt",".cer",".p7b",".p7c",".raw",".txt",".json",".md",".tmp",".bak"},extension)>=0;
    }

    static void CheckInventory(string directory, string root, HashSet<string> seen)
    {
        CheckPath(directory);
        foreach (var entry in Directory.GetFileSystemEntries(directory))
        {
            CheckPath(entry); // Reject junctions before descending into them.
            if ((File.GetAttributes(entry) & FileAttributes.Directory) != 0)
                CheckInventory(entry, root, seen);
            else
            {
                var relative = entry.Substring(root.Length + 1).Replace('\\', '/');
                if (relative == "OfflineKeyVault.exe" || relative == "manifest.sha256" || relative == ".offline-key-vault-upgrade") continue;
                if (!seen.Contains(relative) && !IsUserData(relative)) throw new IOException("Unexpected package file: " + relative);
            }
        }
    }
    static void CheckPath(string path)
    {
        for (var current = new FileInfo(path).FullName; current != null; current = Path.GetDirectoryName(current))
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Links and reparse points are not supported.");
            if (current == Path.GetPathRoot(current)) break;
        }
    }
    static string HashFile(string file)
    {
        // Antivirus/indexing can briefly deny sharing just after extraction.
        // Keep read-only sharing and re-check paths; never relax access rights.
        for (int attempt = 0; ; attempt++)
        {
            CheckPath(file);
            try
            {
                using (var stream = File.OpenRead(file))
                using (var sha = SHA256.Create())
                    return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            }
            catch (IOException error)
            {
                int code = error.HResult & 0xffff;
                if (attempt >= 4 || (code != 32 && code != 33)) throw;
                System.Threading.Thread.Sleep(50 * (1 << attempt));
            }
        }
    }
    static void Verify(string root)
    {
        var manifest = Path.Combine(root, "manifest.sha256");
        CheckPath(manifest);
        // Hash and parse the same snapshot; a mutable checksum list is not trust.
        byte[] manifestBytes;
        using (var stream = File.OpenRead(manifest))
        {
            if (stream.Length > 4 * 1024 * 1024) throw new IOException("Manifest too large.");
            using (var buffer = new MemoryStream())
            {
                stream.CopyTo(buffer);
                manifestBytes = buffer.ToArray();
            }
        }
        using (var sha = SHA256.Create())
        {
            var actual = BitConverter.ToString(sha.ComputeHash(manifestBytes)).Replace("-", "").ToLowerInvariant();
            if (!String.Equals(actual, ManifestSha256, StringComparison.Ordinal))
                throw new IOException("Manifest does not match this launcher.");
        }
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in new UTF8Encoding(false, true).GetString(manifestBytes).Split(new[] {'\n'}, StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Length < 67 || line.Substring(64, 2) != "  ") throw new IOException("Invalid manifest.");
            var relative = line.Substring(66);
            if (relative.Contains("\\") || relative.Contains(":") || Path.IsPathRooted(relative)) throw new IOException("Invalid manifest path.");
            foreach (var part in relative.Split('/'))
                if (part == ".." || part == "." || part.Length == 0) throw new IOException("Invalid manifest path.");
            if (!seen.Add(relative)) throw new IOException("Duplicate manifest entry.");
            var file = Path.GetFullPath(Path.Combine(root, relative));
            if (!file.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Invalid manifest path.");
            CheckPath(file);
            if (!String.Equals(HashFile(file), line.Substring(0, 64), StringComparison.Ordinal))
                throw new IOException("Package checksum failed: " + relative);
        }
        foreach (var required in new[] {"runtime/pythonw.exe", "runtime/python.exe", "runtime/python312._pth", "app/launch.py"})
            if (!seen.Contains(required)) throw new IOException("Incomplete manifest.");
        CheckInventory(root, root, seen);
    }
    [STAThread]
    static int Main(string[] args)
    {
        bool diagnostic = args.Length == 1 && (args[0] == "--self-test" || args[0] == "--verify");
        try
        {
            if (diagnostic)
            {
                // WinExe has redirected handles but may have no console device.
                Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true });
                Console.SetError(new StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false)) { AutoFlush = true });
            }
            if (args.Length > 0 && !diagnostic) throw new ArgumentException("Unsupported arguments.");
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
            if(File.Exists(Path.Combine(root,".offline-key-vault-upgrade")) && !(diagnostic&&args[0]=="--verify"))
                throw new IOException("升级尚未完成。请关闭程序并重新运行安装器，自动恢复后再启动。");
            if (root.StartsWith(@"\\")) throw new IOException("Extract to a local directory first.");
            var drive = new DriveInfo(Path.GetPathRoot(root));
            if (drive.DriveType != DriveType.Fixed && drive.DriveType != DriveType.Removable)
                throw new IOException("A local drive is required.");
            Verify(root);
            if (diagnostic && args[0] == "--verify") { Console.WriteLine("Package checksums OK"); return 0; }
            var runtime = Path.Combine(root, "runtime");
            var start = new ProcessStartInfo();
            start.FileName = Path.Combine(runtime, diagnostic ? "python.exe" : "pythonw.exe");
            start.Arguments = "-I -S -B \"" + Path.Combine(root, "app", "launch.py") + "\"" + (diagnostic ? " --self-test" : "");
            start.WorkingDirectory = root;
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardOutput = diagnostic;
            start.RedirectStandardError = true;
            foreach (var name in new[] {"PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "TCLLIBPATH", "OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES"})
                start.EnvironmentVariables.Remove(name);
            start.EnvironmentVariables["TCL_LIBRARY"] = Path.Combine(runtime, @"tcl\tcl8.6");
            start.EnvironmentVariables["TK_LIBRARY"] = Path.Combine(runtime, @"tcl\tk8.6");
            start.EnvironmentVariables["PATH"] = runtime + ";" + Path.Combine(runtime, "DLLs") + ";" + Environment.GetFolderPath(Environment.SpecialFolder.System);
            using (var process = new Process())
            {
                process.StartInfo = start;
                // Drain stderr to prevent deadlock, but never persist stack traces or locals.
                process.ErrorDataReceived += (sender, e) => { };
                process.Start();
                process.BeginErrorReadLine();
                if (diagnostic) Console.Write(process.StandardOutput.ReadToEnd());
                process.WaitForExit();
                if (process.ExitCode != 0) throw new IOException("Application failed. Re-extract the trusted package or run the offline self-test.");
                return 0;
            }
        }
        catch (Exception error)
        {
            if (diagnostic) Console.Error.WriteLine(error.Message);
            else MessageBox.Show("启动失败：请完整解压到本地目录，不要在 ZIP 内运行。\n\n" + error.Message, "离线密钥柜", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
