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

Running under IIS specifically
--------------------------------
Short answer: the dashboard itself (ReconDash.html) runs under IIS with
zero changes - it's a static file, and IIS serves static files natively.
Serving the CSVs also works natively once you add one MIME type. The
only piece IIS can't do out of the box is the /api/log write, because
plain IIS doesn't execute arbitrary scripts - you need one small addition
for that. Two ways to get all three pieces working under IIS:

  OPTION A - pure IIS + ASP.NET (no Node, no extra modules)
  Recommended if Node isn't an approved runtime on the box.
    1. In IIS Manager, add a new site (or virtual directory) with its
       physical path set to the folder containing ReconDash.html.
    2. Add a virtual directory named "data" under that site, physical
       path C:\Data, with "Enable content browsing" off and static file
       serving on (default).
    3. IIS will 404.3 ("MIME type not allowed") on .csv by default - add
       a MIME type: IIS Manager -> your site -> MIME Types -> Add ->
       File name extension ".csv", MIME type "text/csv". (Or add it via
       the included web.config, see below.)
    4. Make sure ASP.NET is enabled: Windows Features -> Internet
       Information Services -> World Wide Web Services -> Application
       Development Features -> ASP.NET (3.5 and/or 4.8, whichever your
       server has). This is on by default on most IIS installs already
       running other ASP.NET apps.
    5. Create a folder "api" under the site, and place the included
       log.ashx in it. It answers POST /api/log and appends to
       C:\Logs\svl071-console-YYYY-MM-DD.log the same way server.js
       does - no server.js/Node needed with this option.
    6. In the console: Settings -> Data source -> base URL = "/data/",
       Settings -> Activity logging -> endpoint = "/api/log". Both are
       already the defaults, so nothing to change unless your virtual
       directory names differ.
    7. The account IIS runs the app pool as (typically
       IIS AppPool\<sitename> or a configured service account) needs
       read access to C:\Data and write access to C:\Logs - grant those
       in Windows folder permissions if requests come back 500/403.

  OPTION B - keep server.js, put IIS in front of it
  Use this if you'd rather keep one Node process instead of ASP.NET.
    1. Install Node 18+ and run server.js as a background Windows
       service (e.g. via NSSM: `nssm install SVL071Console node.exe
       C:\path\to\server.js`), listening on a local port like 8080.
    2. Install the IIS Application Request Routing (ARR) and URL
       Rewrite modules (both free Microsoft add-ons, not built into a
       stock IIS install).
    3. Add a URL Rewrite reverse-proxy rule sending all traffic for the
       site to http://localhost:8080/. IIS then just fronts the Node
       process; server.js still does the actual file read/log write.
    This gets you IIS's TLS/auth/logging in front, without rewriting
    the log endpoint - more moving parts to install (ARR + Rewrite),
    less code to touch.

For most locked-down bank/enterprise IIS boxes, Option A is usually the
path of least resistance since it needs nothing beyond ASP.NET, which
is almost always already there.

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
