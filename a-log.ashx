<%@ WebHandler Language="C#" Class="LogHandler" %>

// SVL-071 console - /api/log endpoint for plain IIS + ASP.NET (no Node,
// no IISNode, no ARR needed). Drop this file as api/log.ashx under the
// site root so it answers POST /api/log, exactly like server.js's
// endpoint does. Requires ASP.NET to be enabled in IIS (Turn Windows
// features on/off -> Internet Information Services -> World Wide Web
// Services -> Application Development Features -> ASP.NET), which is
// on by default on most Windows Server IIS installs.
//
// It appends one JSON-derived line per POST to
//   C:\Logs\svl071-console-YYYY-MM-DD.log
// matching the format server.js writes, so both are interchangeable.

using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Script.Serialization;

public class LogHandler : IHttpHandler
{
    // Change this if your log folder differs from C:\Logs\.
    private const string LogDir = @"C:\Logs";

    public void ProcessRequest(HttpContext context)
    {
        var response = context.Response;
        response.ContentType = "text/plain";

        if (context.Request.HttpMethod != "POST")
        {
            response.StatusCode = 405;
            response.Write("Method not allowed. POST JSON here.");
            return;
        }

        string body;
        using (var reader = new StreamReader(context.Request.InputStream))
            body = reader.ReadToEnd();

        try
        {
            var serializer = new JavaScriptSerializer();
            var entry = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(body);

            string time = entry.ContainsKey("time") && entry["time"] != null
                ? entry["time"].ToString()
                : DateTime.UtcNow.ToString("o");

            string level = entry.ContainsKey("level") && entry["level"] != null
                ? entry["level"].ToString()
                : "INFO";
            var validLevels = new[] { "OFF", "ERROR", "WARN", "INFO", "DEBUG" };
            if (Array.IndexOf(validLevels, level) < 0) level = "INFO";

            string message = entry.ContainsKey("message") && entry["message"] != null
                ? entry["message"].ToString()
                : "";

            string metaJson = entry.ContainsKey("meta") && entry["meta"] != null
                ? serializer.Serialize(entry["meta"])
                : null;

            if (!Directory.Exists(LogDir)) Directory.CreateDirectory(LogDir);

            string day = Regex.IsMatch(time, @"^\d{4}-\d{2}-\d{2}")
                ? time.Substring(0, 10)
                : DateTime.UtcNow.ToString("yyyy-MM-dd");
            string logFile = Path.Combine(LogDir, "svl071-console-" + day + ".log");

            string line = "[" + time + "] [" + level + "] " + message +
                (metaJson != null ? " " + metaJson : "") + Environment.NewLine;

            File.AppendAllText(logFile, line);

            response.StatusCode = 204;
        }
        catch (Exception ex)
        {
            response.StatusCode = 400;
            response.Write("Bad log payload: " + ex.Message);
        }
    }

    public bool IsReusable { get { return true; } }
}
