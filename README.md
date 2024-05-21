# CISA-parser

Each week, CISA publishes a list of vulnerabilities on their website and via
email. The list is usually long, and tedious to read through since it consists
mostly of programs you have never heard of and are unlikely to run.

**cisa-parser.py** is a Python script that converts the weekly list into a more
compact form to make it easier to scan for items of interest.

- all items for a given vendor/product are grouped together
- details are hidden unless you expand them, making the document much shorter
  and easier to scan
- items on a user-configured list of vendors or products are shown in red
  and expanded to make them more noticable.

## Usage

You can see a list of recent Weekly Vulnerability Summaries at
https://www.cisa.gov/news-events/bulletins.
You can also sign up to receive each week's summary via email.

To use cisa-parser
- edit the "vendors_of_interest" list in cisa-parser.py to include vendors
  and programs of interest to you (probably NOT the list in this repo unless
  you have cloned me as well as my repo)
  
- copy the URL of the desired summary.

  *For example* **https://www.cisa.gov/news-events/bulletins/sb24-141**
  
- run "cisa-parser.py {URL}"

  *For example*  **cisa-parser.py https://www.cisa.gov/news-events/bulletins/sb24-141**
  
- the program will save an html file with a name based on the URL

  *For example*  **sb24-141.html**

- Open the html output in a browser


## Caveats

- You are a much better Python programmer than I am, and could certainly
implement this is one tenth as much code.

- CISA seems to amuse themselves by changing the HTML formatting of the list
from time to time. The current version of cisa-parser matches the structure as
of 13 May 2024, such as this sample at
https://www.cisa.gov/news-events/bulletins/sb24-141
If they change the format and I am still using this program, I will update
this repository.
