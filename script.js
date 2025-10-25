// Secure Code Analyzer - Client-side JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize drag and drop for file upload
    initializeFileUpload();
    
    // Initialize code highlighting
    if (typeof Prism !== 'undefined') {
        Prism.highlightAll();
    }
    
    // Initialize copy to clipboard functionality
    initializeClipboard();
});

function initializeFileUpload() {
    const uploadForm = document.getElementById('uploadForm');
    const fileInput = document.getElementById('file');
    
    if (!uploadForm || !fileInput) return;
    
    // Create drag and drop zone
    const dropZone = document.createElement('div');
    dropZone.className = 'upload-zone mb-3';
    dropZone.innerHTML = `
        <i class="fas fa-cloud-upload-alt fa-3x text-muted mb-3"></i>
        <h5>Drag and drop your file here</h5>
        <p class="text-muted">or click to browse</p>
    `;
    
    // Insert drop zone before file input
    fileInput.parentNode.insertBefore(dropZone, fileInput);
    
    // Handle drag and drop events
    dropZone.addEventListener('dragover', function(e) {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    
    dropZone.addEventListener('dragleave', function(e) {
        e.preventDefault();
        dropZone.classList.remove('dragover');
    });
    
    dropZone.addEventListener('drop', function(e) {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            updateFileInfo(files[0]);
        }
    });
    
    // Handle click to browse
    dropZone.addEventListener('click', function() {
        fileInput.click();
    });
    
    // Handle file input change
    fileInput.addEventListener('change', function(e) {
        if (e.target.files.length > 0) {
            updateFileInfo(e.target.files[0]);
        }
    });
}

function updateFileInfo(file) {
    const dropZone = document.querySelector('.upload-zone');
    if (!dropZone) return;
    
    const allowedTypes = ['php', 'js'];
    const fileExtension = file.name.split('.').pop().toLowerCase();
    
    if (!allowedTypes.includes(fileExtension)) {
        showAlert('Invalid file type. Please select a PHP (.php) or JavaScript (.js) file.', 'danger');
        return;
    }
    
    if (file.size > 16 * 1024 * 1024) {
        showAlert('File size must be less than 16MB.', 'danger');
        return;
    }
    
    // Update drop zone with file info
    dropZone.innerHTML = `
        <i class="fas fa-file-code fa-3x text-success mb-3"></i>
        <h5>${file.name}</h5>
        <p class="text-muted">
            ${(file.size / 1024).toFixed(1)} KB • ${fileExtension.toUpperCase()}
            <br>
            <small>Click to change file</small>
        </p>
    `;
}

function showAlert(message, type = 'info') {
    const alertContainer = document.querySelector('.container');
    if (!alertContainer) return;
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Insert at the top of the container
    alertContainer.insertBefore(alert, alertContainer.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alert.parentNode) {
            alert.remove();
        }
    }, 5000);
}

function initializeClipboard() {
    // Add copy buttons to code blocks
    const codeBlocks = document.querySelectorAll('pre code');
    codeBlocks.forEach(function(codeBlock) {
        const pre = codeBlock.parentElement;
        const copyButton = document.createElement('button');
        copyButton.className = 'btn btn-sm btn-outline-secondary position-absolute top-0 end-0 m-2';
        copyButton.innerHTML = '<i class="fas fa-copy"></i>';
        copyButton.title = 'Copy to clipboard';
        
        // Position relative for absolute positioning of button
        pre.style.position = 'relative';
        pre.appendChild(copyButton);
        
        copyButton.addEventListener('click', function() {
            navigator.clipboard.writeText(codeBlock.textContent).then(function() {
                copyButton.innerHTML = '<i class="fas fa-check text-success"></i>';
                setTimeout(() => {
                    copyButton.innerHTML = '<i class="fas fa-copy"></i>';
                }, 2000);
            }).catch(function(err) {
                console.error('Failed to copy: ', err);
                showAlert('Failed to copy to clipboard', 'warning');
            });
        });
    });
}

// Utility function to format file sizes
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Enhanced search functionality for vulnerabilities
function initializeVulnerabilitySearch() {
    const searchInput = document.getElementById('vulnSearch');
    if (!searchInput) return;
    
    const vulnerabilityItems = document.querySelectorAll('.accordion-item');
    
    searchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        
        vulnerabilityItems.forEach(function(item) {
            const content = item.textContent.toLowerCase();
            if (content.includes(searchTerm)) {
                item.style.display = '';
            } else {
                item.style.display = 'none';
            }
        });
    });
}

// Filter vulnerabilities by severity
function filterBySeverity(severity) {
    const vulnerabilityItems = document.querySelectorAll('.accordion-item');
    
    vulnerabilityItems.forEach(function(item) {
        const badge = item.querySelector('.badge');
        if (!severity || !badge) {
            item.style.display = '';
        } else {
            const itemSeverity = badge.textContent.toLowerCase().trim();
            if (itemSeverity === severity.toLowerCase()) {
                item.style.display = '';
            } else {
                item.style.display = 'none';
            }
        }
    });
}

// Export functionality
function exportReport(reportId, format = 'json') {
    const exportUrl = `/api/report/${reportId}`;
    
    if (format === 'json') {
        window.open(exportUrl, '_blank');
    } else {
        // Could implement PDF export here
        showAlert('PDF export not yet implemented', 'info');
    }
}

// Theme management
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-bs-theme', newTheme);
    localStorage.setItem('theme', newTheme);
}

// Load saved theme
const savedTheme = localStorage.getItem('theme');
if (savedTheme) {
    document.documentElement.setAttribute('data-bs-theme', savedTheme);
}

// Progressive enhancement for better UX
if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
            }
        });
    });
    
    document.querySelectorAll('.card').forEach(function(card) {
        observer.observe(card);
    });
}

// Add fade-in animation CSS
const fadeInStyle = document.createElement('style');
fadeInStyle.textContent = `
    .fade-in {
        animation: fadeInUp 0.6s ease-out;
    }
    
    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(fadeInStyle);
