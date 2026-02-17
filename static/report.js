const linksInput = document.getElementById('links-input');
const linksPreview = document.getElementById('links-preview');
const submitBtn = document.getElementById('submit-btn');
const form = document.getElementById('report-form');
const errorDiv = document.getElementById('error');
const formView = document.getElementById('form-view');
const successView = document.getElementById('success-view');

let parsedLinks = [];

const initialDataElement = document.getElementById('initial-data');
if (initialDataElement) {
    try {
        const initialData = JSON.parse(initialDataElement.textContent);
        initialDataElement.remove();
        displayReportStatus(initialData);
    } catch {
        // Invalid JSON, continue normally
    }
} else {
    const hash = window.location.hash.substring(1);
    if (hash) {
        const parts = hash.split(':');
        const code = parts[0];
        const token = parts[1] || '';
        const origin = window.location.origin;
        const url = token ? `${origin}/${code}#${token}` : `${origin}/${code}`;
        linksInput.value = url;
        updateLinksPreview();
    }
}

function parseRipplitUrl(url) {
    try {
        url = url.trim();
        if (!url) return null;

        const u = new URL(url);
        const path = u.pathname;
        const hash = u.hash.substring(1);

        const codeMatch = path.match(/\/([a-zA-Z0-9_-]+)\+?$/);
        if (!codeMatch) return null;

        const code = codeMatch[1];
        if (!code || code.length > 24 || code.length === 6) return null;
        if (!/^[a-zA-Z0-9_-]+$/.test(code)) return null;
        if (code.startsWith('-') || code.endsWith('-')) return null;

        return {
            code: code,
            token: hash || null,
        };
    } catch {
        return null;
    }
}

function updateLinksPreview() {
    const text = linksInput.value;
    const lines = text.split('\n').filter((line) => line.trim());

    if (lines.length === 0) {
        linksPreview.classList.remove('show');
        parsedLinks = [];
        return;
    }

    const allParsed = lines.map((line) => {
        const parsed = parseRipplitUrl(line);
        return {
            original: line,
            parsed: parsed,
            valid: parsed !== null,
        };
    });

    const validLinks = allParsed.filter((l) => l.valid);
    const invalidLinks = allParsed.filter((l) => !l.valid);
    const seenCodes = new Map();

    validLinks.forEach((link) => {
        const code = link.parsed.code;
        if (!seenCodes.has(code)) {
            seenCodes.set(code, link.parsed.token);
        } else if (link.parsed.token && !seenCodes.get(code)) {
            seenCodes.set(code, link.parsed.token);
        }
    });

    parsedLinks = Array.from(seenCodes.entries()).map(([code, token]) => ({
        parsed: { code, token },
        valid: true,
    }));

    const duplicateCount = validLinks.length - parsedLinks.length;

    let statusText = `${parsedLinks.length} link${parsedLinks.length !== 1 ? 's' : ''}`;
    if (duplicateCount > 0) {
        statusText += ` (${duplicateCount} duplicate${duplicateCount !== 1 ? 's' : ''} removed)`;
    }
    if (invalidLinks.length > 0) {
        statusText += `, ${invalidLinks.length} invalid`;
    }

    linksPreview.innerHTML = '';

    const title = document.createElement('div');
    title.className = 'links-preview-title';
    title.textContent = statusText;
    linksPreview.appendChild(title);

    const invalidToShow = invalidLinks.slice(0, 4);
    const validToShow = parsedLinks.slice(0, 4 - invalidToShow.length);
    const remainingCount = parsedLinks.length - validToShow.length;

    invalidToShow.forEach((link) => {
        const item = document.createElement('div');
        item.className = 'links-preview-item';

        const error = document.createElement('span');
        error.className = 'links-preview-error';
        const truncated = link.original.substring(0, 40);
        error.textContent = `Invalid: ${truncated}${link.original.length > 40 ? '...' : ''}`;

        item.appendChild(error);
        linksPreview.appendChild(item);
    });

    validToShow.forEach((link) => {
        const item = document.createElement('div');
        item.className = 'links-preview-item';

        const code = document.createElement('span');
        code.className = 'links-preview-code';
        code.textContent = link.parsed.code;
        item.appendChild(code);

        if (link.parsed.token) {
            const token = document.createElement('span');
            token.className = 'links-preview-token';
            const truncated = link.parsed.token.substring(0, 12);
            token.textContent = truncated + (link.parsed.token.length > 12 ? '...' : '');
            item.appendChild(token);
        } else {
            const noToken = document.createElement('span');
            noToken.className = 'links-preview-no-token';
            noToken.textContent = 'no token';
            item.appendChild(noToken);
        }

        linksPreview.appendChild(item);
    });

    if (remainingCount > 0) {
        const item = document.createElement('div');
        item.className = 'links-preview-item';

        const more = document.createElement('span');
        more.className = 'links-preview-code';
        more.textContent = `...and ${remainingCount} more`;

        item.appendChild(more);
        linksPreview.appendChild(item);
    }

    linksPreview.classList.add('show');
}

linksInput.addEventListener('input', updateLinksPreview);

async function displayReportStatus(data) {
    formView.style.display = 'none';
    successView.classList.add('show');

    const reportUrl = `${window.location.origin}/report/${data.report_token}`;
    document.getElementById('report-url-display').textContent = reportUrl;
    document.getElementById('report-reason').textContent = formatReason(data.reason);
    document.getElementById('report-count').textContent = data.links.length;

    const linksStatusContainer = document.getElementById('links-status-container');
    linksStatusContainer.innerHTML = '';

    if (data.links.length === 1) {
        const link = data.links[0];
        const isRemoved = link.status.includes('_removed');
        let targetUrl = link.link_url || (isRemoved ? 'Removed' : 'Loading...');

        const grid = document.createElement('div');
        grid.className = 'report-grid';
        grid.style.marginBottom = '1rem';

        const codeCell = document.createElement('div');
        codeCell.className = 'report-cell';
        const codeLabel = document.createElement('div');
        codeLabel.className = 'report-cell-label';
        codeLabel.textContent = 'Link Code';
        const codeValue = document.createElement('div');
        codeValue.className = 'report-cell-value';
        codeValue.textContent = link.code;
        codeCell.appendChild(codeLabel);
        codeCell.appendChild(codeValue);

        const urlCell = document.createElement('div');
        urlCell.className = 'report-cell';
        const urlLabel = document.createElement('div');
        urlLabel.className = 'report-cell-label';
        urlLabel.textContent = 'Target URL';
        const urlValue = document.createElement('div');
        urlValue.className = 'report-cell-value report-cell-url';
        if (isRemoved) urlValue.classList.add('removed');
        urlValue.textContent = targetUrl;
        urlCell.appendChild(urlLabel);
        urlCell.appendChild(urlValue);

        grid.appendChild(codeCell);
        grid.appendChild(urlCell);

        const timeline = document.createElement('div');
        timeline.className = 'status-timeline';

        const title = document.createElement('div');
        title.className = 'status-title';
        title.textContent = 'Review Process';

        const steps = document.createElement('div');
        steps.className = 'status-steps';

        for (let i = 0; i < 3; i++) {
            const dot = document.createElement('div');
            dot.className = 'status-dot';
            dot.dataset.status = ['automated', 'investigating', 'dismissed'][i];
            steps.appendChild(dot);
        }

        const labels = document.createElement('div');
        labels.className = 'status-labels';

        ['Automated', 'Review', 'Dismissed'].forEach((text, i) => {
            const label = document.createElement('div');
            label.className = 'status-label';
            label.dataset.status = ['automated', 'investigating', 'dismissed'][i];
            label.textContent = text;
            labels.appendChild(label);
        });

        timeline.appendChild(title);
        timeline.appendChild(steps);
        timeline.appendChild(labels);

        linksStatusContainer.appendChild(grid);
        linksStatusContainer.appendChild(timeline);

        updateStatusTimeline(link.status);
    } else {
        data.links.forEach((link) => {
            const isRemoved = link.status.includes('_removed');
            const isDismissed = link.status === 'dismissed';
            let targetUrl = link.link_url || (isRemoved ? 'Removed' : 'Loading...');

            const timeline = document.createElement('div');
            timeline.className = 'status-timeline';
            timeline.style.marginBottom = '0.6rem';
            timeline.style.padding = '0.5rem';

            const header = document.createElement('div');
            header.style.display = 'flex';
            header.style.justifyContent = 'space-between';
            header.style.alignItems = 'center';
            header.style.marginBottom = '0.3rem';

            const titleDiv = document.createElement('div');
            titleDiv.className = 'status-title';
            titleDiv.style.marginBottom = '0';
            titleDiv.textContent = link.code;
            header.appendChild(titleDiv);

            const urlCell = document.createElement('div');
            urlCell.className = 'report-cell';
            urlCell.style.marginBottom = '0.4rem';
            urlCell.style.padding = '0.4rem';

            const urlLabel = document.createElement('div');
            urlLabel.className = 'report-cell-label';
            urlLabel.textContent = 'Target URL';

            const urlValue = document.createElement('div');
            urlValue.className = 'report-cell-value report-cell-url';
            urlValue.style.fontSize = '0.65rem';
            if (isRemoved) urlValue.classList.add('removed');
            urlValue.textContent = targetUrl;

            urlCell.appendChild(urlLabel);
            urlCell.appendChild(urlValue);

            const steps = document.createElement('div');
            steps.className = 'status-steps';
            steps.style.marginBottom = '0.3rem';

            const dot1 = document.createElement('div');
            dot1.className = 'status-dot';
            if (link.status === 'automated' || link.status === 'automated_removed') {
                dot1.classList.add('active');
            } else {
                dot1.classList.add('completed');
            }
            if (link.status === 'automated_removed') dot1.classList.add('removed');

            const dot2 = document.createElement('div');
            dot2.className = 'status-dot';
            if (link.status === 'investigating' || link.status === 'investigating_removed') {
                dot2.classList.add('active');
            } else if (link.status.includes('investigating') || isDismissed) {
                dot2.classList.add('completed');
            }
            if (link.status === 'investigating_removed') dot2.classList.add('removed');

            const dot3 = document.createElement('div');
            dot3.className = 'status-dot';
            if (isDismissed) {
                dot3.classList.add('dismissed', 'active');
            }

            steps.appendChild(dot1);
            steps.appendChild(dot2);
            steps.appendChild(dot3);

            const labels = document.createElement('div');
            labels.className = 'status-labels';

            const label1 = document.createElement('div');
            label1.className = 'status-label';
            if (link.status === 'automated' || link.status === 'automated_removed') {
                label1.classList.add('active');
            }
            if (link.status === 'automated_removed') label1.classList.add('removed');
            label1.textContent = 'Automated';

            const label2 = document.createElement('div');
            label2.className = 'status-label';
            if (link.status === 'investigating' || link.status === 'investigating_removed') {
                label2.classList.add('active');
            }
            if (link.status === 'investigating_removed') label2.classList.add('removed');
            label2.textContent = 'Review';

            const label3 = document.createElement('div');
            label3.className = 'status-label';
            if (isDismissed) label3.classList.add('dismissed', 'active');
            label3.textContent = 'Dismissed';

            labels.appendChild(label1);
            labels.appendChild(label2);
            labels.appendChild(label3);

            timeline.appendChild(header);
            timeline.appendChild(urlCell);
            timeline.appendChild(steps);
            timeline.appendChild(labels);

            linksStatusContainer.appendChild(timeline);
        });
    }
}

function updateStatusTimeline(status) {
    const dots = document.querySelectorAll('.status-dot');
    const labels = document.querySelectorAll('.status-label');

    const isRemoved = status.includes('_removed');
    const isDismissed = status === 'dismissed';

    if (status === 'automated') {
        dots[0]?.classList.add('active');
        labels[0]?.classList.add('active');
    } else if (status === 'automated_removed') {
        dots[0]?.classList.add('active', 'removed');
        labels[0]?.classList.add('active', 'removed');
    } else if (status === 'investigating') {
        dots[0]?.classList.add('completed');
        dots[1]?.classList.add('active');
        labels[1]?.classList.add('active');
    } else if (status === 'investigating_removed') {
        dots[0]?.classList.add('completed');
        dots[1]?.classList.add('active', 'removed');
        labels[1]?.classList.add('active', 'removed');
    } else if (status === 'dismissed') {
        dots[0]?.classList.add('completed');
        dots[1]?.classList.add('completed');
        dots[2]?.classList.add('active', 'dismissed');
        labels[2]?.classList.add('active', 'dismissed');
    }
}

function formatReason(reason) {
    const reasons = {
        malware: 'Malware / Phishing',
        spam: 'Spam',
        csam: 'Child Sexual Abuse Material',
        violence: 'Violence / Gore',
        harassment: 'Harassment / Hate Speech',
        copyright: 'Copyright Violation',
        other: 'Other',
    };
    return reasons[reason] || reason;
}

form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const validLinks = parsedLinks.filter((l) => l.valid);

    if (validLinks.length === 0) {
        showError('Please add at least one valid link');
        return;
    }

    if (validLinks.length > 100) {
        showError('Maximum 100 links per report');
        return;
    }

    const links = validLinks.map((l) => ({
        code: l.parsed.code,
        token: l.parsed.token,
    }));

    const reason = document.getElementById('reason').value;
    const description = document.getElementById('description').value;

    if (!reason || !description.trim()) {
        showError('Please fill in all fields');
        return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting...';

    try {
        const reportData = {
            links: links,
            reason: reason,
            description: description.trim(),
        };

        const reportToken = await window.captchaHandler.handleSubmit(reportData, submitBtn);

        if (reportToken === null) {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Submit';
            return;
        }

        window.location.href = `/report/${reportToken}`;
    } catch (error) {
        showError(error.message || 'Failed to submit report');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Submit';
    }
});

function showError(message) {
    errorDiv.textContent = message;
    errorDiv.classList.add('show');
    setTimeout(() => errorDiv.classList.remove('show'), 5000);
}
