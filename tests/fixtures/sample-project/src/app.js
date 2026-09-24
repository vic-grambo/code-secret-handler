// Sample JavaScript file with hardcoded secrets
const stripe = require('stripe');
const client = stripe('sk_test_XXXX1234567890XXXX1234'); // fake key for testing

const GITHUB_TOKEN = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789';

const db = require('pg');
const pool = new db.Pool({
  connectionString: 'postgres://admin:supersecretpassword123@db.example.com:5432/mydb',
});

const jwtSecret = 'my-super-secret-jwt-signing-key-2024';

module.exports = { pool };
