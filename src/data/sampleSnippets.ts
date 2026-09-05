export interface SampleScenario {
  id: string;
  name: string;
  filename: string;
  category: string;
  language: string;
  description: string;
  code: string;
}

export const SAMPLE_SCENARIOS: SampleScenario[] = [
  {
    id: 'sample-express-api',
    name: 'Node/Express Authentication Service',
    filename: 'auth-service.ts',
    category: 'Secrets & Injection',
    language: 'TypeScript',
    description: 'Contains hardcoded AWS tokens, SQL injection via template string, and unpinned dependencies.',
    code: `import express from 'express';
import { Pool } from 'pg';
import crypto from 'crypto';

const app = express();
const db = new Pool();

// Hardcoded AWS credentials in code
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const JWT_SECRET = "super_secret_jwt_key_123456";

app.use(express.json());

// SQL Injection via direct template interpolation
app.get('/api/users/search', async (req, res) => {
  const searchTerm = req.query.q;
  const sql = \`SELECT id, username, email FROM users WHERE username LIKE '%\${searchTerm}%'\`;
  const result = await db.query(sql);
  res.json(result.rows);
});

// Remote Command Injection via child_process
import { exec } from 'child_process';
app.post('/api/diagnostics/ping', (req, res) => {
  const host = req.body.host;
  exec("ping -c 1 " + host, (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    res.send(stdout);
  });
});

// Weak MD5 Password Hash
function hashPassword(password: string) {
  return crypto.createHash('md5').update(password).digest('hex');
}

export default app;`,
  },
  {
    id: 'sample-python-flask',
    name: 'Python Flask Data Pipeline',
    filename: 'app.py',
    category: 'RCE & Path Traversal',
    language: 'Python',
    description: 'Demonstrates Python pickle insecure deserialization, path traversal, and debug mode.',
    code: `from flask import Flask, request, jsonify, send_file
import pickle
import os

app = Flask(__name__)
# Dangerous debug mode enabled
app.config['DEBUG'] = True

# Insecure object deserialization via pickle
@app.route('/api/import-state', methods=['POST'])
def import_state():
    raw_payload = request.get_data()
    data = pickle.loads(raw_payload) # Remote Code Execution vulnerability
    return jsonify({"status": "imported", "keys": list(data.keys())})

# Arbitrary File Read / Path Traversal
@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('file')
    # Path traversal with ../
    file_path = os.path.join('/var/reports', filename)
    with open(file_path, 'r') as f:
        return f.read()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)`,
  },
  {
    id: 'sample-docker-iac',
    name: 'Docker & CI/CD Infrastructure',
    filename: 'Dockerfile',
    category: 'IaC Misconfiguration',
    language: 'Docker',
    description: 'Dockerfile running as root user with untrusted curl-pipe-bash script installation.',
    code: `# Insecure Dockerfile Configuration
FROM node:latest

WORKDIR /usr/src/app

# Dangerous unpinned remote script pipe to bash
RUN apt-get update && apt-get install -y curl && \\
    curl -sSL https://raw.githubusercontent.com/example/cli/master/install.sh | bash

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 8080

# Missing USER nonroot directive - container executes as root
CMD ["node", "server.js"]`,
  },
  {
    id: 'sample-react-frontend',
    name: 'React Frontend with DOM XSS',
    filename: 'UserWidget.tsx',
    category: 'XSS Vulnerability',
    language: 'React',
    description: 'Direct dangerouslySetInnerHTML injection of user biography and exposed Stripe secret keys.',
    code: `import React from 'react';

// Hardcoded Stripe Secret Key (Placeholder)
const STRIPE_SECRET = 'REDACTED';

export function UserBioWidget({ bioHtml, username }: { bioHtml: string; username: string }) {
  return (
    <div className="profile-card">
      <h3>{username}</h3>
      {/* Dangerous unescaped HTML injection */}
      <div 
        className="bio-content" 
        dangerouslySetInnerHTML={{ __html: bioHtml }} 
      />
    </div>
  );
}`,
  },
];
