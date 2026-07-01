const express = require('express');
const app = express();
app.use(express.json());

// Mock Database
const db = {
    records: {
        "101": { id: "101", owner_id: "user_a", diagnosis: "Hypertension", meds: "Lisinopril" },
        "102": { id: "102", owner_id: "user_b", diagnosis: "Diabetes", meds: "Metformin" }
    }
};

// Mock Authentication Middleware
function authenticate(req, res, next) {
    // In reality, this would verify a JWT. We mock it for the PoC.
    const token = req.headers['authorization'];
    if (token === 'Bearer token_user_a') {
        req.user = { id: 'user_a' };
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
}

app.get('/api/v1/patient/record/:record_id', authenticate, (req, res) => {
    const recordId = req.params.record_id;
    const record = db.records[recordId];

    if (!record) {
        return res.status(404).json({ error: 'Record not found' });
    }

    /*
     * VULNERABILITY: Broken Object Level Authorization (BOLA / IDOR)
     * The application verifies the user is logged in (via the authenticate middleware),
     * but fails to verify if the logged-in user actually owns the requested record.
     */
     
    // MISSING CHECK: if (record.owner_id !== req.user.id) { return 403; }

    // SINK: Returns sensitive medical data to potentially unauthorized users
    res.json({ status: 'success', data: record });
});

// To run locally for testing:
if (require.main === module) {
    console.log("Mock Regulated Node.js Patient API (BOLA Target)");
    // app.listen(3000, () => console.log('Server running on port 3000'));
}

module.exports = app;
