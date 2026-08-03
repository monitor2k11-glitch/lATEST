SVL-071 CONSOLE - DATA FOLDER + LOGGING SETUP
================================================

Why a browser can't just "read C:\Data\"
-----------------------------------------
ReconDash.html runs entirely inside the user's browser. A web page has no
API to open an arbitrary local path like C:\Data\ or C:\Logs\ - that would
let any website on the internet read your hard drive. The only thing a
page can do is send HTTP requests. So "auto-load from C:\Data\" has to
become "auto-load from a URL that a web server maps to C:\Data\", and
"log to C:\Logs\" has to become "POST each entry to a URL, and have the
server write it to C:\Logs\".

Fastest path: the included server.js
-------------------------------------
1. Install Node.js 18+ on the machine that will host the console (no
   other packages needed - server.js only uses Node's built-ins).
2. Put ReconDash.html and server.js in the same folder.
3. Make sure C:\Data\ contains the CSVs named exactly as configured in
   Settings -> File Loader / Data Import (defaults: source_staging_
   summary.csv, staging_transform_summary.csv, transform_publish_
   summary.csv, break_details.csv, lookup_failures.csv, risk_enrichment_
   failures.csv, final_records.csv). Make sure C:\Logs\ exists or is
   creatable by the account running the process.
4. Run:
       node server.js
   (or set DATA_DIR / LOG_DIR / PORT environment variables first if your
   paths or port differ from the C:\Data\, C:\Logs\, 8080 defaults).
5. Open http://localhost:8080/ (or the server's real hostname if other
   people need to reach it). Settings -> Data source is already pointed
   at "/data/", which this server serves straight from C:\Data\, and
   Settings -> Activity logging is already pointed at "/api/log", which
   this server appends to C:\Logs\svl071-console-YYYY-MM-DD.log.

Already have IIS / Apache / nginx / a different backend?
----------------------------------------------------------
You don't need server.js at all - the console only needs two things from
whatever server hosts it:

  1. GET  <baseUrl><filename>.csv   ->  serves the matching file from
     C:\Data\. In IIS this is usually just pointing a virtual directory
     at C:\Data\ with static file serving enabled; static file servers
     handle this natively.

  2. POST /api/log   ->   receives a JSON body shaped like
     { "time": "...", "level": "INFO", "message": "...", "meta": {...} }
     and appends one line to a file under C:\Logs\. This one does need a
     small script/handler (an ASP.NET endpoint, a Python/Flask route, an
     Azure Function, etc.) since static file servers can't accept
     writes - the append logic in server.js's appendLogLine() is about
     20 lines and ports directly to any of those.

Set the matching URLs in Settings -> Data source (base URL) and
Settings -> Activity logging (log endpoint) inside the console itself -
both are editable there, nothing is hardcoded.

Log levels
----------
Settings -> Activity logging -> Log level controls what gets sent and
kept, low to high: OFF, ERROR, WARN, INFO (default), DEBUG. INFO covers
normal load/reload/clear/import activity; DEBUG adds a line per CSV file
per load (row counts, URLs). Entries are always visible in the Settings
page's "Recent activity" panel and downloadable via "Download session
log" regardless of whether the server endpoint is reachable.
