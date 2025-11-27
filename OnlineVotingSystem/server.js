const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Database connection
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'zetech_voting_system'
};

// Create database connection pool
const pool = mysql.createPool(dbConfig);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware to verify token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// Test database connection
app.get('/api/test', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        res.json({ message: 'Database connected successfully' });
        connection.release();
    } catch (error) {
        res.status(500).json({ error: 'Database connection failed' });
    }
});

// Student registration
app.post('/api/register', async (req, res) => {
    try {
        const { student_id, full_name, email, phone, course, password } = req.body;

        // Check if student already exists
        const [existingStudent] = await pool.execute(
            'SELECT * FROM students WHERE student_id = ? OR email = ?',
            [student_id, email]
        );

        if (existingStudent.length > 0) {
            return res.status(400).json({ error: 'Student ID or email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new student
        const [result] = await pool.execute(
            'INSERT INTO students (student_id, full_name, email, phone, course, password_hash) VALUES (?, ?, ?, ?, ?, ?)',
            [student_id, full_name, email, phone, course, hashedPassword]
        );

        res.status(201).json({ 
            message: 'Registration successful',
            studentId: result.insertId 
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Student login
app.post('/api/login', async (req, res) => {
    try {
        const { student_id, password } = req.body;

        // Find student
        const [students] = await pool.execute(
            'SELECT * FROM students WHERE student_id = ?',
            [student_id]
        );

        if (students.length === 0) {
            return res.status(400).json({ error: 'Invalid student ID or password' });
        }

        const student = students[0];

        // Check password
        const validPassword = await bcrypt.compare(password, student.password_hash);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid student ID or password' });
        }

        // Create token
        const token = jwt.sign(
            { 
                id: student.id, 
                student_id: student.student_id,
                full_name: student.full_name
            }, 
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            student: {
                id: student.id,
                student_id: student.student_id,
                full_name: student.full_name,
                email: student.email,
                course: student.course,
                has_voted: student.has_voted
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all positions
app.get('/api/positions', async (req, res) => {
    try {
        const [positions] = await pool.execute('SELECT * FROM positions');
        res.json(positions);
    } catch (error) {
        console.error('Positions error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get candidates by position
app.get('/api/candidates/:positionId', async (req, res) => {
    try {
        const { positionId } = req.params;
        const [candidates] = await pool.execute(
            `SELECT c.*, p.title as position_name 
             FROM candidates c 
             JOIN positions p ON c.position_id = p.id 
             WHERE c.position_id = ?`,
            [positionId]
        );
        res.json(candidates);
    } catch (error) {
        console.error('Candidates error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all candidates with position info
app.get('/api/candidates', async (req, res) => {
    try {
        const [candidates] = await pool.execute(
            `SELECT c.*, p.title as position_name 
             FROM candidates c 
             JOIN positions p ON c.position_id = p.id`
        );
        res.json(candidates);
    } catch (error) {
        console.error('Candidates error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Submit vote
app.post('/api/vote', authenticateToken, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        await connection.beginTransaction();
        
        const { votes } = req.body; // Array of { candidate_id, position_id }
        const studentId = req.user.id;

        // Check if student has already voted
        const [existingVotes] = await connection.execute(
            'SELECT * FROM votes WHERE student_id = ?',
            [studentId]
        );

        if (existingVotes.length > 0) {
            await connection.rollback();
            return res.status(400).json({ error: 'You have already voted' });
        }

        // Insert votes
        for (const vote of votes) {
            await connection.execute(
                'INSERT INTO votes (student_id, candidate_id, position_id) VALUES (?, ?, ?)',
                [studentId, vote.candidate_id, vote.position_id]
            );
        }

        // Mark student as voted
        await connection.execute(
            'UPDATE students SET has_voted = TRUE WHERE id = ?',
            [studentId]
        );

        await connection.commit();
        res.json({ message: 'Vote submitted successfully' });
    } catch (error) {
        await connection.rollback();
        console.error('Vote error:', error);
        res.status(500).json({ error: 'Internal server error' });
    } finally {
        connection.release();
    }
});

// Get election results
app.get('/api/results', async (req, res) => {
    try {
        const [results] = await pool.execute(
            `SELECT 
                p.id as position_id,
                p.title as position_name,
                c.id as candidate_id,
                c.name as candidate_name,
                COUNT(v.id) as vote_count,
                (SELECT COUNT(*) FROM votes v2 WHERE v2.position_id = p.id) as total_votes
             FROM positions p
             LEFT JOIN candidates c ON p.id = c.position_id
             LEFT JOIN votes v ON c.id = v.candidate_id
             GROUP BY p.id, c.id
             ORDER BY p.id, vote_count DESC`
        );

        // Calculate percentages
        const formattedResults = results.map(result => ({
            ...result,
            percentage: result.total_votes > 0 
                ? ((result.vote_count / result.total_votes) * 100).toFixed(2)
                : 0
        }));

        res.json(formattedResults);
    } catch (error) {
        console.error('Results error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Check if student has voted
app.get('/api/check-vote-status', authenticateToken, async (req, res) => {
    try {
        const [votes] = await pool.execute(
            'SELECT * FROM votes WHERE student_id = ?',
            [req.user.id]
        );

        res.json({ hasVoted: votes.length > 0 });
    } catch (error) {
        console.error('Check vote error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Backend API accessible at: http://localhost:${PORT}/api`);
});