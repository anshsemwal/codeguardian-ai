"""
Utility helper functions
"""

import re
import hashlib
from typing import Dict, List, Any, Optional
import difflib

def parse_diff(diff_content: str) -> Dict[str, Any]:
    """Parse diff content and extract changes"""
    
    parsed_diff = {
        'files': [],
        'additions': 0,
        'deletions': 0,
        'total_changes': 0
    }
    
    if not diff_content:
        return parsed_diff
    
    lines = diff_content.split('\n')
    current_file = None
    
    for line in lines:
        # File header
        if line.startswith('diff --git'):
            if current_file:
                parsed_diff['files'].append(current_file)
            
            # Extract filenames
            match = re.search(r'a/(.+?) b/(.+?)$', line)
            if match:
                current_file = {
                    'old_path': match.group(1),
                    'new_path': match.group(2),
                    'additions': 0,
                    'deletions': 0,
                    'changes': []
                }
        
        # Addition
        elif line.startswith('+') and not line.startswith('+++'):
            parsed_diff['additions'] += 1
            if current_file:
                current_file['additions'] += 1
                current_file['changes'].append({
                    'type': 'addition',
                    'line': line[1:],
                    'line_number': None  # Would need more parsing to get exact line numbers
                })
        
        # Deletion
        elif line.startswith('-') and not line.startswith('---'):
            parsed_diff['deletions'] += 1
            if current_file:
                current_file['deletions'] += 1
                current_file['changes'].append({
                    'type': 'deletion',
                    'line': line[1:],
                    'line_number': None
                })
    
    # Add the last file
    if current_file:
        parsed_diff['files'].append(current_file)
    
    parsed_diff['total_changes'] = parsed_diff['additions'] + parsed_diff['deletions']
    
    return parsed_diff

def extract_changed_files(files_data: List[Dict[str, Any]]) -> List[str]:
    """Extract list of changed file paths"""
    
    changed_files = []
    for file_data in files_data:
        filename = file_data.get('filename') or file_data.get('new_path') or file_data.get('old_path')
        if filename:
            changed_files.append(filename)
    
    return changed_files

def calculate_file_hash(content: str) -> str:
    """Calculate SHA256 hash of file content"""
    
    if not content:
        return ""
    
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def extract_functions_from_python_code(code: str) -> List[Dict[str, Any]]:
    """Extract function definitions from Python code"""
    
    functions = []
    lines = code.split('\n')
    
    for i, line in enumerate(lines, 1):
        # Match function definitions
        match = re.match(r'^\s*(def|async def)\s+(\w+)\s*\(', line)
        if match:
            functions.append({
                'name': match.group(2),
                'line': i,
                'type': 'async' if 'async' in match.group(1) else 'sync',
                'definition': line.strip()
            })
    
    return functions

def extract_classes_from_python_code(code: str) -> List[Dict[str, Any]]:
    """Extract class definitions from Python code"""
    
    classes = []
    lines = code.split('\n')
    
    for i, line in enumerate(lines, 1):
        # Match class definitions
        match = re.match(r'^\s*class\s+(\w+)', line)
        if match:
            classes.append({
                'name': match.group(1),
                'line': i,
                'definition': line.strip()
            })
    
    return classes

def extract_imports_from_python_code(code: str) -> List[Dict[str, Any]]:
    """Extract import statements from Python code"""
    
    imports = []
    lines = code.split('\n')
    
    for i, line in enumerate(lines, 1):
        line = line.strip()
        
        # Match import statements
        if line.startswith('import ') or line.startswith('from '):
            imports.append({
                'line': i,
                'statement': line,
                'type': 'from' if line.startswith('from') else 'import'
            })
    
    return imports

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage"""
    
    # Remove or replace dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Limit length
    if len(sanitized) > 255:
        sanitized = sanitized[:255]
    
    return sanitized

def truncate_text(text: str, max_length: int = 1000, suffix: str = "...") -> str:
    """Truncate text to specified length"""
    
    if not text:
        return ""
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes/1024:.1f} KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes/(1024**2):.1f} MB"
    else:
        return f"{size_bytes/(1024**3):.1f} GB"

def calculate_similarity(text1: str, text2: str) -> float:
    """Calculate similarity between two texts (0-1)"""
    
    if not text1 or not text2:
        return 0.0
    
    # Use difflib to calculate similarity
    matcher = difflib.SequenceMatcher(None, text1, text2)
    return matcher.ratio()

def extract_code_blocks_from_markdown(markdown_text: str) -> List[Dict[str, Any]]:
    """Extract code blocks from markdown text"""
    
    code_blocks = []
    lines = markdown_text.split('\n')
    in_code_block = False
    current_block = []
    language = None
    start_line = 0
    
    for i, line in enumerate(lines):
        if line.strip().startswith('```'):
            if not in_code_block:
                # Start of code block
                in_code_block = True
                language = line.strip()[3:].strip() or None
                start_line = i + 1
                current_block = []
            else:
                # End of code block
                in_code_block = False
                code_blocks.append({
                    'language': language,
                    'code': '\n'.join(current_block),
                    'start_line': start_line,
                    'end_line': i
                })
                current_block = []
                language = None
        elif in_code_block:
            current_block.append(line)
    
    return code_blocks

def validate_git_url(url: str) -> bool:
    """Validate if URL is a valid git repository URL"""
    
    git_patterns = [
        r'^https://github\.com/[\w\-\.]+/[\w\-\.]+/?',
        r'^https://gitlab\.com/[\w\-\.]+/[\w\-\.]+/?',
        r'^git@github\.com:[\w\-\.]+/[\w\-\.]+\.git',
        r'^git@gitlab\.com:[\w\-\.]+/[\w\-\.]+\.git'
    ]
    
    return any(re.match(pattern, url) for pattern in git_patterns)

def extract_repo_info_from_url(url: str) -> Optional[Dict[str, str]]:
    """Extract owner and repo name from git URL"""
    
    # GitHub HTTPS
    match = re.match(r'https://github\.com/([\w\-\.]+)/([\w\-\.]+)/?', url)
    if match:
        return {
            'platform': 'github',
            'owner': match.group(1),
            'name': match.group(2)
        }
    
    # GitLab HTTPS
    match = re.match(r'https://gitlab\.com/([\w\-\.]+)/([\w\-\.]+)/?', url)
    if match:
        return {
            'platform': 'gitlab', 
            'owner': match.group(1),
            'name': match.group(2)
        }
    
    # GitHub SSH
    match = re.match(r'git@github\.com:([\w\-\.]+)/([\w\-\.]+)\.git', url)
    if match:
        return {
            'platform': 'github',
            'owner': match.group(1),
            'name': match.group(2)
        }
    
    # GitLab SSH
    match = re.match(r'git@gitlab\.com:([\w\-\.]+)/([\w\-\.]+)\.git', url)
    if match:
        return {
            'platform': 'gitlab',
            'owner': match.group(1),
            'name': match.group(2)
        }
    
    return None

def generate_review_id() -> str:
    """Generate unique review ID"""
    
    import uuid
    return str(uuid.uuid4())[:8]

def format_duration(seconds: float) -> str:
    """Format duration in human readable format"""
    
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"

def clean_code_snippet(code: str, max_lines: int = 10) -> str:
    """Clean and truncate code snippet for display"""
    
    if not code:
        return ""
    
    lines = code.split('\n')
    
    # Remove empty lines at start and end
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    
    # Truncate if too long
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines.append("... (truncated)")
    
    return '\n'.join(lines)

def is_test_file(filename: str) -> bool:
    """Check if file is a test file"""
    
    test_patterns = [
        r'test_.*\.py',
        r'.*_test\.py',
        r'tests?/.*\.py',
        r'.*test.*\.py'
    ]
    
    return any(re.search(pattern, filename.lower()) for pattern in test_patterns)

def is_config_file(filename: str) -> bool:
    """Check if file is a configuration file"""
    
    config_patterns = [
        r'.*\.json',
        r'.*\.yml',
        r'.*\.yaml',
        r'.*\.toml',
        r'.*\.ini',
        r'.*\.cfg',
        r'.*config.*',
        r'requirements.*\.txt',
        r'setup\.py',
        r'Dockerfile',
        r'docker-compose\.yml'
    ]
    
    return any(re.search(pattern, filename.lower()) for pattern in config_patterns)

def get_file_language(filename: str) -> str:
    """Determine programming language from filename"""
    
    extension_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.java': 'java',
        '.go': 'go',
        '.rs': 'rust',
        '.cpp': 'cpp',
        '.c': 'c',
        '.cs': 'csharp',
        '.php': 'php',
        '.rb': 'ruby',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.scala': 'scala',
        '.sh': 'bash',
        '.sql': 'sql',
        '.html': 'html',
        '.css': 'css',
        '.scss': 'scss',
        '.less': 'less'
    }
    
    ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
    return extension_map.get(ext, 'text')