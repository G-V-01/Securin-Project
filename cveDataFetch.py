import mysql.connector
import requests

# Set up connection parameters
host = '127.0.0.1'
user = 'root'
password = '@Guru2003'
database = 'CVE'

# Establish a connection to the database
try:
    connection = mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=database
    )
    print("Connected to MySQL database!")
except mysql.connector.Error as err:
    print("Error:", err)
    exit()

cursor = connection.cursor()

# Example SQL query
query = "SHOW TABLES;"

# Execute the query
cursor.execute(query)

# Fetch all rows
rows = cursor.fetchall()

# Process the fetched rows
for row in rows:
    print(row)

# Close the cursor and connection
# cursor.close()

api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
response = requests.get(api_url)

if response.status_code == 200:
    data = response.json()
    
    for cve_item in data["vulnerabilities"]:
        try:
            cve_id = cve_item["cve"]["id"]
            source = cve_item["cve"]["sourceIdentifier"]
            published = cve_item["cve"]["published"]
            last_modified = cve_item["cve"]["lastModified"]
            vulnerability_status = cve_item["cve"]["vulnStatus"]
            access_vector = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["accessVector"]
            access_complexity = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["accessComplexity"]
            authentication = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["authentication"]
            confidentiality_impact = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["confidentialityImpact"]
            score = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
            base_severity = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["baseSeverity"]
            exploitability_score = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["exploitabilityScore"]
            impact_score = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["impactScore"]
            integrity_impact = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["integrityImpact"]
            availability_impact = cve_item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["availabilityImpact"]
            criteria = cve_item["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"]
            match_criteria_id = cve_item["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["matchCriteriaId"]
            vulnerable = cve_item["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["vulnerable"]
            description = cve_item["cve"]["descriptions"][0]["value"]
            
            # Example: Insert into database
            insert_query = "INSERT INTO CVE_List (CVE_ID, IDENTIFIER, PUBLISHED_DATE, LAST_MODIFIED_DATE, STATUS, ACCESS_VECTOR, ACCESS_COMPLEXITY, AUTHENTICATION, CONFIDENTIALITY_IMPACT, INTEGRITY_IMPACT, AVAILABILITY_IMPACT, CRITERIA, MATCH_CRITERIA_ID, VULNERABLE, DESCRIPTION, BASE_SEVERITY, SCORE, EXPLOITABILITY_SCORE, IMPACT_SCORE) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            values = (cve_id, source, published, last_modified, vulnerability_status, access_vector, access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, criteria, match_criteria_id, vulnerable, description, base_severity, score, exploitability_score, impact_score)
            cursor.execute(insert_query, values)
            connection.commit()
            print(f"Data for CVE_ID {cve_id} inserted successfully!")
        except mysql.connector.IntegrityError as e:
            print(f"Duplicate entry for CVE_ID {cve_id}. Skipping insert.")
        except KeyError as e:
            print(f"Skipping CVE item due to missing key: {e}")
            continue
        except Exception as ex:
            print(f"Error occurred: {ex}")
else:
    print("Failed to fetch data from NVD API")

# Close the connection
cursor.close()
connection.close()
