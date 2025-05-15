Description : 
    
  Webscrapping tool is used for scrape the website in a specific pattern by using the Python's library (BeautifulSoup and request).After the scraping analyze and filter for required information.
  After scraping the scraped information is stored in CSV file for future use of vulnerability details.
  After storing in the file we taske a copy of the information and send it to the user's email itself.

Information : 
  
    1.Unique-Id
    2.OEM name 
    3.Product Name
    4.Description 
    5.Patch details / links
    6.Severity level/Score
    7.Publish Date

Requirements : 

For sending the email to ourself we need 

    1.Email (example@gmail.com)
    2.App password  (XXXX XXXX XXXX XXXX)

Setting up App password: 

    1.Setup the 2-Step Verification
    2.Search 
          * Type "App Password"
          * Type "App Name" 
          * Click "Generate" Button.
          * Shows 12 digit letters (XXXX XXXX XXXX XXXX)
    3.Update the APP PASSWORD to the "sender_password" variable.
    
  
  
