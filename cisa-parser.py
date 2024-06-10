#!/usr/bin/python
# Parse the Weekly CISA Vulnerability List to make it easier to scan for items of interest
#
# By John Hartman. Released into the public domain

import sys
import urllib.parse as url_parse
import urllib.request as url_req
from html.parser import HTMLParser

g_version = "1.1"

#==============================================================================
# List of vendors/products of special interest (to me).
# Items whose Vendor/Product field contains any of these will be shown in red
# and expanded by default.
# Yes, this could be a separate configuration file, but why?
vendors_of_interest = ['apple', 'ios', 'microsoft', 'windows', \
                       'google', 'chrome', 'mozilla', 'firefox', \
                       'adobe', 'symantec', \
                       'dell', 'epson', 'acer', 'asus', \
                       'ssh', 'nmap', 'wireshark', 'filezilla', '7zip', \
                       'notepad++', 'notepad2', 'freecommander', 'obs', \
                       'reaper', 'zoom', 'musescore', 'shotcut' ]

#==============================================================================
# Parse CISA webpage assuming structure as of 10 April 2024:
# Sample at https://www.cisa.gov/news-events/bulletins/sb24-099
#
# ...
# <div id="high_v">
#    ...
#    <table ...
#       <tbody>
#          <tr>
#             <td class="vendor_product>vendor and product name</td>
#             <td>descriptions</td>
#             <td>published</td>
#             <td>CVSS score</td>
#             <td><a href="source-and-patch-info">...</td>
#     ...
#  <div id="medium_v">
#     ...
#  <div id="low_v">
#     ...
#  <div id="snya_v">
#     ...
#
#-------------------------------------------------------------
# Parsing is via State Machine:
#-------------------------------------------------------------
# Idle
# - tag: td with class 'vendor-product': set state "vendor"
# - endtag: ignore
# - data: ignore
#
# Vendor
# - tag: ignore (assume <br> etc)
# - endtag: use data, td set state "description"
# - data: accumulate (there may be intervening tags)
#
# Description
# - tag: ignore (assume <br> etc)
# - endtag: td set state "published"
# - data: accumulate (there may be intervening tags)
#
# Published
# - tag: ignore (assume <br> etc)
# - endtag: td set state "score"
# - data: ignore, or accumulate (there may be intervening tags)
#
# Score
# - tag: ignore (assume <br> etc)
# - endtag: td set state "source"
# - data: ignore, or accumulate (there may be intervening tags)
#
# Source
# - tag: "a" get URL from attributes, else ignore
# - endtag: td set state idle (possibly missing url)
# - data: ignore

class MyHTMLParser(HTMLParser):
    def __init__(self):
        self.tag_handler = self.tag_idle
        self.end_tag_handler = self.end_tag_ignore
        self.content = ''

        self.vendor = ''
        self.description = ''
        self.priority = ''
        self.url = ''

        self.rows = {}
        super().__init__()

    def tag_ignore(self, tag, attrs):
        pass

    def end_tag_ignore(self, tag):
        pass

    def tag_idle(self, tag, attrs):
        if tag == 'div':
            for attr in attrs:
                if (attr[0] == 'id'):
                    if (attr[1] == 'high_v'):
                        self.priority = 'High'
                    elif (attr[1] == 'medium_v'):
                        self.priority = 'Medium'
                    elif (attr[1] == 'low_v'):
                        self.priority = 'Low'
                    elif (attr[1] == 'snya_v'):
                        self.priority = 'Uncategorized'

        if tag == 'td':
            for attr in attrs:
                if (attr[0] == 'class') and (attr[1] == 'vendor-product'):
                    # Vendor/product. Accumulate data for this item
                    self.tag_handler = self.tag_ignore
                    self.end_tag_handler = self.end_tag_vendor
                    self.content = ''

    def end_tag_vendor(self, tag):
        if tag == 'td':
            # Save/use the vendor/product info. Get Description
            self.vendor = self.content
            self.tag_handler = self.tag_ignore
            self.end_tag_handler = self.end_tag_description
            self.content = ''

    def end_tag_description(self, tag):
        if tag == 'td':
            # Save/use the description info. Get publication date
            self.description = self.content
            self.tag_handler = self.tag_ignore
            self.end_tag_handler = self.end_tag_publication
            self.content = ''

    def end_tag_publication(self, tag):
        if tag == 'td':
            # Save/use the description info. Get publication date
            self.tag_handler = self.tag_ignore
            self.end_tag_handler = self.end_tag_score
            self.content = ''

    def end_tag_score(self, tag):
        if tag == 'td':
            # Save/use the description info. Get publication date
            self.tag_handler = self.tag_source
            self.end_tag_handler = self.end_tag_source
            self.content = ''

    #<td>
    #  <a href="https://nvd.nist.gov/nvd.cfm?cvename=CVE-2024-0335" target="_blank">
    #    CVE-2024-0335</a>
    #  <br>
    #  <a href="https://search.abb.com/library/Download.aspx?DocumentID=7PAA002536&amp;LanguageCode=en&amp;DocumentPartId=&amp;Action=Launch" target="_blank">
    #    cybersecurity@ch.abb.com</a>
    #</td>
    def tag_source(self, tag, attrs):
        if tag == 'a':
            # Get URL
            for attr in attrs:
                if (attr[0] == 'href'):
                    self.url = attr[1]
                    self.tag_handler = self.tag_idle
                    self.end_tag_handler = self.end_tag_ignore
                    self.content = ''
                    self.save_row()

    def end_tag_source(self, tag):
        if tag == 'td':
            # Item has no URL
            self.url = ''
            self.tag_handler = self.tag_idle
            self.end_tag_handler = self.end_tag_ignore
            self.content = ''
            self.save_row()

    def handle_starttag(self, tag, attrs):
        self.tag_handler(tag, attrs)

    def handle_endtag(self, tag):
        self.end_tag_handler(tag)

    def handle_data(self, data):
        self.content += data.strip()

    # Save the current row for later output
    def save_row(self):
        row = self.priority + ': ' + self.description \
            + ' <a href="' + self.url + '" target="_blank">' \
            + self.url + '</a><hr>'

        if self.vendor in self.rows:
            self.rows[self.vendor] = self.rows[self.vendor] + row
        else:
            self.rows[self.vendor] = row

    # Dump the accumlated data as a web page
    def dump_report(self, url):
        print('Found ' + str(len(self.rows)) + ' items')

        path = url_parse.urlparse(url).path.split('/')
        filename = path[len(path) - 1]
        with open(filename + '.html', 'w', encoding="utf-8") as outfile:
            outfile.write( '<!DOCTYPE html>\n<html lang="en" dir="ltr">\n' \
                         + '<head>\n<title>Vulnerability Summary ' + filename \
                         + '</title>\n<meta charset="utf-8">\n</head>\n<body>\n' \
                         + '<h1>Content from <a href="' + url \
                         + '" target="_blank">' + url + '</a></h1>')

            for i in sorted(self.rows.keys(), key=str.lower):
                lc_vendor = i.lower()
                color = 'black'
                state = ''
                for interest in vendors_of_interest:
                    if interest in lc_vendor:
                        color = 'red'
                        state = ' open'
                        break

                outfile.write( '  <details' + state + '>\n' \
                             + '    <summary style="font-size:1.2em;' \
                             + ' color:' + color + ';">' + i + '</summary>\n' \
                             + '    <div style="margin-left:40px">' \
                             + self.rows[i] + '</div>\n</details>\n')

            outfile.write('</body>\n</html>\n')

#==============================================================================
def main():
    infile_name = ''
    if (len(sys.argv) <= 1):
        print(
"""Parse a CISA Weekly Vulnerability Summary to make it easier to scan.
- Sorts vendor/product alphabetically, even if CISA messes it up again.
- Groups all items for the same vendor/product together
- Hides details for each vendor/product in an expander
- If the Vendor/Product section of an item contains a keyword found
  in the "vendors_of_interest" table, that item is shown in red and expanded.

Usage: cisa-parser.py {url}')
- {url} URL of the CISA webpage to be parsed')
- output filename is the last section of the URL (typically sbYY-ZZZ)
""")
        return

    print('cisa-parser version ' + g_version)

    url = sys.argv[1]
    req = url_req.Request(url, headers={'User-Agent': ' Mozilla/5.0'})
    client = url_req.urlopen(req)
    htmldata = client.read()

    parser = MyHTMLParser()
    parser.feed(htmldata.decode('utf-8'))

    parser.dump_report(url)

#==============================================================================
if __name__ == "__main__":    
    main()

