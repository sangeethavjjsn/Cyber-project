from flask import render_template, request, redirect, url_for, flash, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
from app import app, db
from models import AnalysisReport
from analyzer import SecurityAnalyzer

ALLOWED_EXTENSIONS = {'php', 'js'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    recent_reports = AnalysisReport.query.order_by(AnalysisReport.upload_time.desc()).limit(5).all()
    return render_template('index.html', recent_reports=recent_reports)

@app.route('/upload')
def upload_page():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze the file
        try:
            analyzer = SecurityAnalyzer()
            file_type = filename.rsplit('.', 1)[1].lower()
            
            with open(filepath, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            analysis_result = analyzer.analyze_code(code_content, file_type)
            
            # Create analysis report
            report = AnalysisReport(
                filename=filename,
                file_type=file_type,
                file_size=os.path.getsize(filepath),
                security_score=analysis_result['security_score'],
                total_vulnerabilities=analysis_result['total_vulnerabilities'],
                critical_count=analysis_result['severity_counts']['critical'],
                high_count=analysis_result['severity_counts']['high'],
                medium_count=analysis_result['severity_counts']['medium'],
                low_count=analysis_result['severity_counts']['low']
            )
            report.set_vulnerabilities(analysis_result['vulnerabilities'])
            
            db.session.add(report)
            db.session.commit()
            
            # Clean up uploaded file
            os.remove(filepath)
            
            flash('File analyzed successfully!', 'success')
            return redirect(url_for('view_results', report_id=report.id))
            
        except Exception as e:
            # Clean up uploaded file
            if os.path.exists(filepath):
                os.remove(filepath)
            flash(f'Error analyzing file: {str(e)}', 'error')
            return redirect(url_for('upload_page'))
    else:
        flash('Invalid file type. Please upload PHP or JavaScript files only.', 'error')
        return redirect(request.url)

@app.route('/results/<int:report_id>')
def view_results(report_id):
    report = AnalysisReport.query.get_or_404(report_id)
    vulnerabilities = report.get_vulnerabilities()
    return render_template('results.html', report=report, vulnerabilities=vulnerabilities)

@app.route('/api/report/<int:report_id>')
def get_report_json(report_id):
    report = AnalysisReport.query.get_or_404(report_id)
    
    report_data = {
        'id': report.id,
        'filename': report.filename,
        'file_type': report.file_type,
        'file_size': report.file_size,
        'upload_time': report.upload_time.isoformat(),
        'analysis_time': report.analysis_time.isoformat(),
        'security_score': report.security_score,
        'total_vulnerabilities': report.total_vulnerabilities,
        'severity_counts': {
            'critical': report.critical_count,
            'high': report.high_count,
            'medium': report.medium_count,
            'low': report.low_count
        },
        'vulnerabilities': report.get_vulnerabilities()
    }
    
    return jsonify(report_data)

@app.route('/reports')
def list_reports():
    page = request.args.get('page', 1, type=int)
    reports = AnalysisReport.query.order_by(AnalysisReport.upload_time.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    return render_template('reports.html', reports=reports)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
