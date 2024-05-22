const express = require('express');
const mysql = require('mysql');
const path = require('path');
const app = express();
const cors = require('cors');

app.use(cors());
const port = 3000;

// MySQL database connection configuration
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '@Guru2003',
    database: 'CVE' // Your database name
});

// Connect to MySQL database
connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Page-1.html'));
});

app.get('/Page-2.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'Page-2.html'));
});

// API endpoint to fetch CVE data
app.get('/cve', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const countQuery = 'SELECT COUNT(*) AS total FROM CVE_List';
    const dataQuery = 'SELECT CVE_ID, IDENTIFIER, PUBLISHED_DATE, LAST_MODIFIED_DATE, STATUS FROM CVE_List LIMIT ? OFFSET ?';
    const values = [limit, offset];

    connection.query(countQuery, (err, countResults) => {
        if (err) {
            console.error('Error executing count query:', err.message);
            res.status(500).json({ error: 'Internal server error' });
            return;
        }

        const totalRecords = countResults[0].total;

        connection.query(dataQuery, values, (err, dataResults) => {
            if (err) {
                console.error('Error executing data query:', err.message);
                res.status(500).json({ error: 'Internal server error' });
                return;
            }

            res.json({ total: totalRecords, data: dataResults });
        });
    });
});

// API endpoint to fetch CVE details and serve Page-2.html
app.get('/cve-details/:cveId', (req, res) => {
    res.sendFile(path.join(__dirname, 'Page-2.html'));
});

// API endpoint to fetch detailed CVE information
app.get('/get-details', (req, res) => {
    const cveId = req.query.cveId; // Extract CVE ID from query parameters
    const query = 'SELECT CVE_ID, ACCESS_VECTOR, ACCESS_COMPLEXITY, DESCRIPTION, AUTHENTICATION, CONFIDENTIALITY_IMPACT, INTEGRITY_IMPACT, AVAILABILITY_IMPACT, CRITERIA, MATCH_CRITERIA_ID, VULNERABLE, SCORE, BASE_SEVERITY, EXPLOITABILITY_SCORE, IMPACT_SCORE FROM CVE_List WHERE CVE_ID = ?';
    const values = [cveId];

    console.log('Received request for CVE ID:', cveId);
    console.log('Executing MySQL query:', query, values);

    connection.query(query, values, (err, results) => {
        if (err) {
            console.error('Error executing MySQL query:', err.message);
            res.status(500).json({ error: 'Internal server error' });
            return;
        }

        // Check if any results were found for the specified CVE ID
        if (results.length === 0) {
            res.status(404).json({ error: 'CVE not found' });
            return;
        }
        console.log('Query results:', results);

        // Format the fetched data
        const formattedResult = {
            cveId: results[0].CVE_ID,
            description: results[0].DESCRIPTION,
            cvssMetrics: {
                severity: results[0].BASE_SEVERITY,
                score: results[0].SCORE,
                exploitabilityScore: results[0].EXPLOITABILITY_SCORE,
                impactScore: results[0].IMPACT_SCORE
            },
            cpeList: [
                {
                    cpe: results[0].CRITERIA,
                    criteria: results[0].CRITERIA,
                    matchCriteriaId: results[0].MATCH_CRITERIA_ID,
                    vulnerable: results[0].VULNERABLE
                }
            ],
            cpeeMetrics: {
                accessVector: results[0].ACCESS_VECTOR,
                accessComplexity: results[0].ACCESS_COMPLEXITY,
                authentication: results[0].AUTHENTICATION,
                confidentialityImpact: results[0].CONFIDENTIALITY_IMPACT,
                integrityImpact: results[0].INTEGRITY_IMPACT,
                availabilityImpact: results[0].AVAILABILITY_IMPACT
            }
        };

        res.json(formattedResult);
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
