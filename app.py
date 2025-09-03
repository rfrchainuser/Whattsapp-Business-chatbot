from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
import json
import os
from datetime import datetime
import sqlite3
from io import BytesIO
import requests

# Optional dependencies for Excel import/export
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'whatsapp_business_secret_key_2024')
app.config['ENV'] = 'production'
app.config['DEBUG'] = False
app.config['TESTING'] = False

# Database initialization
def init_db():
    conn = sqlite3.connect('whatsapp_business.db')
    cursor = conn.cursor()
    
    # Create FAQs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS faqs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            parent_id INTEGER DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (parent_id) REFERENCES faqs (id)
        )
    ''')
    
    # Create settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL
        )
    ''')
    
    # Insert default settings
    cursor.execute('''
        INSERT OR IGNORE INTO settings (key, value) VALUES 
        ('whatsapp_api_token', ''),
        ('whatsapp_phone_number', ''),
        ('greeting_message', 'Hello! Welcome to our WhatsApp Business. How can I help you today?')
    ''')
    
    conn.commit()
    conn.close()

# Helper to fetch a setting value by key
def get_setting(key: str, default: str = '') -> str:
    try:
        conn = sqlite3.connect('whatsapp_business.db')
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row and row[0] is not None else default
    except Exception:
        return default

# Initialize database on startup
init_db()

@app.route('/')
def index():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == 'Admin' and password == 'Admin':
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/faqs', methods=['GET'])
def get_faqs():
    conn = sqlite3.connect('whatsapp_business.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, question, answer, parent_id FROM faqs ORDER BY parent_id IS NULL DESC, id')
    faqs = cursor.fetchall()
    conn.close()
    
    # Convert to hierarchical structure
    faq_dict = {}
    root_faqs = []
    
    # First, create all FAQ objects
    for faq in faqs:
        faq_obj = {
            'id': faq[0],
            'question': faq[1],
            'answer': faq[2],
            'parent_id': faq[3],
            'sub_faqs': []
        }
        faq_dict[faq[0]] = faq_obj
        
        if faq[3] is None:  # Root FAQ
            root_faqs.append(faq_obj)
    
    # Then, build hierarchy by adding sub-FAQs to their parents
    for faq in faqs:
        if faq[3] is not None:  # Has parent
            parent_faq = faq_dict.get(faq[3])
            child_faq = faq_dict.get(faq[0])
            if parent_faq and child_faq:
                parent_faq['sub_faqs'].append(child_faq)
    
    return jsonify(root_faqs)

@app.route('/api/faqs', methods=['POST'])
def add_faq():
    data = request.json
    question = data.get('question')
    answer = data.get('answer')
    parent_id = data.get('parent_id')
    
    conn = sqlite3.connect('whatsapp_business.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO faqs (question, answer, parent_id) VALUES (?, ?, ?)', 
                   (question, answer, parent_id))
    faq_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({'id': faq_id, 'question': question, 'answer': answer, 'parent_id': parent_id})

@app.route('/api/faqs/<int:faq_id>', methods=['PUT'])
def update_faq(faq_id):
    data = request.json
    question = data.get('question')
    answer = data.get('answer')
    
    conn = sqlite3.connect('whatsapp_business.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE faqs SET question = ?, answer = ? WHERE id = ?', 
                   (question, answer, faq_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/faqs/<int:faq_id>', methods=['DELETE'])
def delete_faq(faq_id):
    conn = sqlite3.connect('whatsapp_business.db')
    cursor = conn.cursor()
    # Delete sub-FAQs first
    cursor.execute('DELETE FROM faqs WHERE parent_id = ?', (faq_id,))
    # Delete main FAQ
    cursor.execute('DELETE FROM faqs WHERE id = ?', (faq_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/settings', methods=['GET'])
def get_settings():
    conn = sqlite3.connect('whatsapp_business.db')
    cursor = conn.cursor()
    cursor.execute('SELECT key, value FROM settings')
    settings = dict(cursor.fetchall())
    conn.close()
    
    return jsonify(settings)

@app.route('/api/settings', methods=['POST'])
def update_settings():
    data = request.json
    
    conn = sqlite3.connect('whatsapp_business.db')
    cursor = conn.cursor()
    
    for key, value in data.items():
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', 
                       (key, value))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json
    message = data.get('message', '').lower()
    
    # Get greeting message
    conn = sqlite3.connect('whatsapp_business.db')
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM settings WHERE key = ?', ('greeting_message',))
    greeting = cursor.fetchone()
    greeting_msg = greeting[0] if greeting else 'Hello! How can I help you?'
    
    # Get all FAQs for suggestions
    cursor.execute('SELECT id, question, answer, parent_id FROM faqs WHERE parent_id IS NULL ORDER BY id')
    faqs = cursor.fetchall()
    conn.close()
    
    faq_suggestions = [{'id': faq[0], 'question': faq[1], 'answer': faq[2]} for faq in faqs]
    
    return jsonify({
        'response': greeting_msg,
        'suggestions': faq_suggestions
    })

@app.route('/api/faq-answer/<int:faq_id>')
def get_faq_answer(faq_id):
    conn = sqlite3.connect('whatsapp_business.db')
    cursor = conn.cursor()
    cursor.execute('SELECT question, answer FROM faqs WHERE id = ?', (faq_id,))
    faq = cursor.fetchone()
    
    # Get sub-FAQs
    cursor.execute('SELECT id, question, answer FROM faqs WHERE parent_id = ?', (faq_id,))
    sub_faqs = cursor.fetchall()
    conn.close()
    
    if faq:
        response = {
            'answer': faq[1],
            'sub_faqs': [{'id': sub[0], 'question': sub[1], 'answer': sub[2]} for sub in sub_faqs]
        }
        return jsonify(response)
    
    return jsonify({'error': 'FAQ not found'}), 404


@app.route('/api/export-faqs')
def export_faqs():
    if not PANDAS_AVAILABLE or not OPENPYXL_AVAILABLE:
        return jsonify({'error': 'Excel export not available - pandas/openpyxl not installed'}), 400
    
    conn = sqlite3.connect('whatsapp_business.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, question, answer, parent_id FROM faqs ORDER BY id')
    faqs = cursor.fetchall()
    conn.close()
    
    # Create DataFrame
    df_data = []
    for faq in faqs:
        df_data.append({
            'ID': faq[0],
            'Question': faq[1],
            'Answer': faq[2],
            'Parent_ID': faq[3] if faq[3] else '',
            'Type': 'Sub-FAQ' if faq[3] else 'Main FAQ'
        })
    
    df = pd.DataFrame(df_data)
    
    # Create Excel file in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='FAQs', index=False)
    
    output.seek(0)
    
    return send_file(
        output,
        as_attachment=True,
        download_name='whatsapp_faqs.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )


@app.route('/api/import-faqs', methods=['POST'])
def import_faqs():
    if not PANDAS_AVAILABLE or not OPENPYXL_AVAILABLE:
        return jsonify({'success': False, 'error': 'Excel import not available - pandas/openpyxl not installed'}), 400
    
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not file.filename.lower().endswith(('.xlsx', '.xls')):
            return jsonify({'success': False, 'error': 'Please upload an Excel file (.xlsx or .xls)'}), 400
        
        # Read Excel file
        df = pd.read_excel(file)
        
        # Validate required columns
        required_columns = ['Question', 'Answer']
        if not all(col in df.columns for col in required_columns):
            return jsonify({'success': False, 'error': f'Excel file must contain columns: {", ".join(required_columns)}'}), 400
        
        conn = sqlite3.connect('whatsapp_business.db')
        cursor = conn.cursor()
        
        # Clear existing FAQs
        cursor.execute('DELETE FROM faqs')
        
        # Import FAQs from Excel
        id_mapping = {}  # Map old IDs to new IDs for parent relationships
        
        # First pass: Import main FAQs (no parent)
        for _, row in df.iterrows():
            question = str(row['Question']).strip()
            answer = str(row['Answer']).strip()
            
            # Skip if Parent_ID exists and is not empty (these are sub-FAQs)
            has_parent = False
            if 'Parent_ID' in df.columns and pd.notna(row['Parent_ID']) and str(row['Parent_ID']).strip():
                has_parent = True
            
            if question and answer and not has_parent:
                cursor.execute('INSERT INTO faqs (question, answer, parent_id) VALUES (?, ?, ?)',
                              (question, answer, None))
                new_id = cursor.lastrowid
                
                # Map old ID to new ID if ID column exists
                if 'ID' in df.columns and pd.notna(row['ID']):
                    old_id = str(int(float(row['ID']))).strip()  # Convert to int first, then string
                    if old_id:
                        id_mapping[old_id] = new_id
        
        # Second pass: Import sub-FAQs with correct parent references
        for _, row in df.iterrows():
            question = str(row['Question']).strip()
            answer = str(row['Answer']).strip()
            
            # Only process sub-FAQs (those with Parent_ID)
            if 'Parent_ID' in df.columns and pd.notna(row['Parent_ID']) and str(row['Parent_ID']).strip():
                try:
                    parent_id_str = str(int(float(row['Parent_ID']))).strip()  # Convert to int first, then string
                    parent_id = id_mapping.get(parent_id_str)  # Get new parent ID
                    
                    if question and answer and parent_id:
                        cursor.execute('INSERT INTO faqs (question, answer, parent_id) VALUES (?, ?, ?)',
                                      (question, answer, parent_id))
                except (ValueError, TypeError):
                    # Skip if Parent_ID conversion fails
                    continue
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': f'Successfully imported {len(df)} FAQs from Excel file'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

# WhatsApp Business Webhook (Verification + Event Receiver)
@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    if request.method == 'GET':
        # Verification challenge from Meta
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')

        verify_token = get_setting('webhook_verify_token', '')

        if mode == 'subscribe' and token == verify_token:
            return challenge, 200
        return 'Forbidden', 403

    # POST: Incoming events/messages
    try:
        body = request.get_json(force=True, silent=True) or {}
        # Log incoming events (production-ready logging)
        app.logger.info(f'[Webhook] Incoming event: {json.dumps(body)}')
        return jsonify({'status': 'received'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# Send Test WhatsApp message via Graph API using saved settings
@app.route('/api/send-test', methods=['POST'])
def send_test_message():
    data = request.json or {}
    to = data.get('to')  # E.164 format, e.g., 15551234567
    text = data.get('message', 'Hello from WB Dashboard!')

    if not to:
        return jsonify({'success': False, 'error': 'Missing "to" phone number'}), 400

    phone_number_id = get_setting('whatsapp_phone_number_id')
    token = get_setting('whatsapp_api_token')

    if not phone_number_id or not token:
        return jsonify({'success': False, 'error': 'Missing phone_number_id or api token in settings'}), 400

    url = f'https://graph.facebook.com/v19.0/{phone_number_id}/messages'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    payload = {
        'messaging_product': 'whatsapp',
        'to': to,
        'type': 'text',
        'text': {'body': text}
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=20)
        ok = resp.status_code in (200, 201)
        return jsonify({
            'success': ok,
            'status_code': resp.status_code,
            'response': resp.json() if resp.content else {}
        }), (200 if ok else 400)
    except requests.RequestException as e:
        return jsonify({'success': False, 'error': str(e)}), 400


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # Production configuration
    app.run(
        debug=False,
        host='0.0.0.0', 
        port=port,
        threaded=True,
        use_reloader=False
    )
