class CaptchaHandler {
    constructor() {
        this.popup = null;
        this.token = null;
        this.image = null;
        this.rounds = [];
        this.currentRound = 0;
        this.currentScene = 0;
        this.answers = [];
        this.resolve = null;
        this.reject = null;
        this.triggerButton = null;
        this.pendingRequest = null;
        this.init();
    }

    init() {
        this.popup = document.createElement('div');
        this.popup.className = 'captcha-popup';
        this.popup.innerHTML = `
      <div class="captcha-header">
        <span class="captcha-round"></span>
        <button class="captcha-close">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="2">
            <path d="M18 6L6 18M6 6l12 12"/>
          </svg>
        </button>
      </div>
      <div class="captcha-prompt">
        Find target icon above fullest cup
      </div>
      <div class="captcha-content">
        <div class="captcha-reference">
          <canvas width="100" height="150"></canvas>
          <div class="captcha-reference-label">Target Icon</div>
        </div>
        <div class="captcha-scenes">
          <canvas class="captcha-scene-canvas" width="150" height="150"></canvas>
          <div class="captcha-controls">
            <button class="captcha-arrow captcha-left">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                   stroke="currentColor" stroke-width="2">
                <path d="M15 18l-6-6 6-6"/>
              </svg>
            </button>
            <div class="captcha-dots"></div>
            <button class="captcha-arrow captcha-right">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                   stroke="currentColor" stroke-width="2">
                <path d="M9 18l6-6-6-6"/>
              </svg>
            </button>
          </div>
        </div>
      </div>
      <button class="captcha-submit">Continue</button>
    `;
        document.body.appendChild(this.popup);

        this.popup.querySelector('.captcha-close').addEventListener('click', () => this.close());
        this.popup
            .querySelector('.captcha-left')
            .addEventListener('click', () => this.navigate(-1));
        this.popup
            .querySelector('.captcha-right')
            .addEventListener('click', () => this.navigate(1));
        this.popup.querySelector('.captcha-submit').addEventListener('click', () => this.submit());

        this.handleKeydown = this.handleKeydown.bind(this);
        this.handleClickOutside = this.handleClickOutside.bind(this);
        this.handleViewportChange = this.handleViewportChange.bind(this);
    }

    handleKeydown(e) {
        if (!this.popup.classList.contains('show')) return;
        if (e.key === 'ArrowLeft') this.navigate(-1);
        if (e.key === 'ArrowRight') this.navigate(1);
        if (e.key === 'Enter') this.submit();
        if (e.key === 'Escape') this.close();
    }

    handleClickOutside(e) {
        if (!this.popup.contains(e.target) && !this.triggerButton?.contains(e.target)) {
            this.close();
        }
    }

    handleViewportChange() {
        if (this.popup.classList.contains('show')) {
            this.position();
        }
    }

    position() {
        if (!this.triggerButton) return;

        const rect = this.triggerButton.getBoundingClientRect();
        const width = 280;
        const height = 360;

        const spaceBelow = window.innerHeight - rect.bottom;
        const spaceAbove = rect.top;

        let top, left;

        if (spaceBelow >= height + 10) {
            top = rect.bottom + 10;
        } else if (spaceAbove >= height + 10) {
            top = rect.top - height - 10;
        } else {
            top = Math.max(10, (window.innerHeight - height) / 2);
        }

        left = rect.left + rect.width / 2 - width / 2;
        left = Math.max(10, Math.min(left, window.innerWidth - width - 10));
        top = Math.max(10, Math.min(top, window.innerHeight - height - 10));

        this.popup.style.top = `${top}px`;
        this.popup.style.left = `${left}px`;
    }

    async show(data, triggerButton) {
        return new Promise((resolve, reject) => {
            this.resolve = resolve;
            this.reject = reject;
            this.triggerButton = triggerButton;
            this.token = data.token;
            this.rounds = data.rounds;
            this.currentRound = 0;
            this.currentScene = 0;
            this.answers = [];

            const img = new Image();
            img.onload = () => {
                this.image = img;
                this.updateRound();
                this.popup.classList.add('show');
                this.position();
                document.addEventListener('keydown', this.handleKeydown);
                document.addEventListener('click', this.handleClickOutside);
                window.addEventListener('resize', this.handleViewportChange);
                window.addEventListener('scroll', this.handleViewportChange, true);
            };
            img.onerror = () => reject(new Error('Failed to load captcha image'));
            img.src = 'data:image/png;base64,' + data.image;
        });
    }

    close() {
        this.popup.classList.remove('show');
        document.removeEventListener('keydown', this.handleKeydown);
        document.removeEventListener('click', this.handleClickOutside);
        window.removeEventListener('resize', this.handleViewportChange);
        window.removeEventListener('scroll', this.handleViewportChange, true);
        if (this.reject) {
            this.reject(new Error('Captcha closed'));
            this.reject = null;
        }
    }

    updateRound() {
        this.currentScene = 0;
        this.popup.querySelector('.captcha-round').textContent =
            `${this.currentRound + 1} of ${this.rounds.length}`;

        const button = this.popup.querySelector('.captcha-submit');
        button.textContent = this.currentRound < this.rounds.length - 1 ? 'Continue' : 'Verify';
        button.disabled = false;

        this.drawReference();
        this.drawScene();
        this.updateDots();
    }

    getRoundOffset() {
        let offset = 0;
        for (let i = 0; i < this.currentRound; i++) {
            offset += 133 + this.rounds[i] * 200;
        }
        return offset;
    }

    drawReference() {
        const canvas = this.popup.querySelector('.captcha-reference canvas');
        const context = canvas.getContext('2d');
        context.clearRect(0, 0, canvas.width, canvas.height);
        context.drawImage(
            this.image,
            this.getRoundOffset(),
            0,
            133,
            200,
            0,
            0,
            canvas.width,
            canvas.height
        );
    }

    drawScene() {
        const canvas = this.popup.querySelector('.captcha-scene-canvas');
        const context = canvas.getContext('2d');
        context.clearRect(0, 0, canvas.width, canvas.height);
        const offset = this.getRoundOffset() + 133 + this.currentScene * 200;
        context.drawImage(this.image, offset, 0, 200, 200, 0, 0, canvas.width, canvas.height);
    }

    updateDots() {
        const container = this.popup.querySelector('.captcha-dots');
        const count = this.rounds[this.currentRound];
        container.innerHTML = '';

        for (let i = 0; i < count; i++) {
            const dot = document.createElement('button');
            dot.className = 'captcha-dot' + (i === this.currentScene ? ' active' : '');
            dot.addEventListener('click', () => {
                this.currentScene = i;
                this.drawScene();
                this.updateDots();
            });
            container.appendChild(dot);
        }
    }

    navigate(direction) {
        const count = this.rounds[this.currentRound];
        this.currentScene = (this.currentScene + direction + count) % count;
        this.drawScene();
        this.updateDots();
    }

    async submit() {
        this.answers.push(this.currentScene);

        if (this.currentRound < this.rounds.length - 1) {
            this.currentRound++;
            this.updateRound();
            return;
        }

        const button = this.popup.querySelector('.captcha-submit');
        button.disabled = true;
        button.textContent = 'Verifying...';

        try {
            const endpoint = this.pendingRequest.reason ? '/api/report' : '/api/shorten';

            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ...this.pendingRequest,
                    captcha_token: this.token,
                    captcha_answers: this.answers,
                }),
            });

            const contentType = response.headers.get('content-type');

            if (!response.ok) {
                const text = await response.text();
                let errorMsg = 'Verification failed';
                try {
                    const data = JSON.parse(text);
                    errorMsg = data.error || errorMsg;
                } catch {}

                this.popup.classList.remove('show');
                document.removeEventListener('keydown', this.handleKeydown);
                document.removeEventListener('click', this.handleClickOutside);
                window.removeEventListener('resize', this.handleViewportChange);
                window.removeEventListener('scroll', this.handleViewportChange, true);

                if (this.reject) {
                    this.reject(new Error(errorMsg));
                    this.reject = null;
                }
                return;
            }

            if (contentType && contentType.includes('application/json')) {
                const data = await response.json();

                if (data.token) {
                    this.token = data.token;
                    this.rounds = data.rounds;
                    this.currentRound = 0;
                    this.answers = [];

                    const img = new Image();
                    img.onload = () => {
                        this.image = img;
                        this.updateRound();
                        this.showError('Incorrect, please try again');
                    };
                    img.onerror = () => {
                        this.showError('Failed to load new challenge');
                        button.disabled = false;
                        button.textContent = 'Verify';
                    };
                    img.src = 'data:image/png;base64,' + data.image;
                    return;
                }

                throw new Error('Unexpected response format');
            }

            const code = await response.text();

            this.popup.classList.remove('show');
            document.removeEventListener('keydown', this.handleKeydown);
            document.removeEventListener('click', this.handleClickOutside);
            window.removeEventListener('resize', this.handleViewportChange);
            window.removeEventListener('scroll', this.handleViewportChange, true);

            if (this.resolve) {
                this.resolve(code);
                this.resolve = null;
            }
        } catch (error) {
            this.showError(error.message || 'Verification failed');
            button.disabled = false;
            button.textContent = 'Verify';
        }
    }

    showError(message) {
        let error = this.popup.querySelector('.captcha-error');
        if (!error) {
            error = document.createElement('div');
            error.className = 'captcha-error';
            this.popup.appendChild(error);
        }
        error.textContent = message;
        setTimeout(() => error.remove(), 3000);
    }

    setPendingRequest(request) {
        this.pendingRequest = request;
    }

    async handleSubmit(requestData, submitButton) {
        try {
            const endpoint = requestData.reason ? '/api/report' : '/api/shorten';

            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestData),
            });

            if (!response.ok) {
                const text = await response.text();
                let errorMsg = 'Failed to submit';
                try {
                    const data = JSON.parse(text);
                    errorMsg = data.error || errorMsg;
                } catch {}
                throw new Error(errorMsg);
            }

            const contentType = response.headers.get('content-type');

            if (contentType && contentType.includes('application/json')) {
                const data = await response.json();

                if (data.token) {
                    this.setPendingRequest(requestData);
                    return await this.show(data, submitButton);
                }

                if (data.error) {
                    throw new Error(data.error);
                }
            }

            return await response.text();
        } catch (error) {
            if (error.message === 'Captcha closed') {
                return null;
            }
            throw error;
        }
    }
}

window.captchaHandler = new CaptchaHandler();

class CaptchaPageHandler {
    constructor(captchaData, code, isPreview, container, errorDiv) {
        this.code = code;
        this.isPreview = isPreview;
        this.container = container;
        this.errorDiv = errorDiv;
        this.token = captchaData.token;
        this.rounds = captchaData.rounds;
        this.currentRound = 0;
        this.currentScene = 0;
        this.answers = [];
        this.image = null;

        this.loadImage(captchaData.image);
    }

    loadImage(base64Image) {
        const img = new Image();
        img.onload = () => {
            this.image = img;
            this.render();
        };
        img.onerror = () => {
            this.showError('Failed to load captcha');
        };
        img.src = 'data:image/png;base64,' + base64Image;
    }

    render() {
        this.container.innerHTML = '';

        const roundInfo = document.createElement('div');
        roundInfo.className = 'captcha-page-round';
        roundInfo.textContent = `Challenge ${this.currentRound + 1} of ${this.rounds.length}`;
        this.container.appendChild(roundInfo);

        const prompt = document.createElement('div');
        prompt.className = 'captcha-page-prompt';
        prompt.textContent = 'Find target icon above fullest cup';
        this.container.appendChild(prompt);

        const challengeArea = document.createElement('div');
        challengeArea.className = 'captcha-page-challenge';

        const referenceDiv = document.createElement('div');
        referenceDiv.className = 'captcha-page-reference';
        const refCanvas = document.createElement('canvas');
        refCanvas.width = 133;
        refCanvas.height = 200;
        const refLabel = document.createElement('div');
        refLabel.className = 'captcha-page-reference-label';
        refLabel.textContent = 'Target Icon';
        referenceDiv.appendChild(refCanvas);
        referenceDiv.appendChild(refLabel);

        const scenesDiv = document.createElement('div');
        scenesDiv.className = 'captcha-page-scenes';
        const sceneCanvas = document.createElement('canvas');
        sceneCanvas.className = 'captcha-page-scene-canvas';
        sceneCanvas.width = 200;
        sceneCanvas.height = 200;
        scenesDiv.appendChild(sceneCanvas);

        const controls = document.createElement('div');
        controls.className = 'captcha-page-controls';

        const leftBtn = document.createElement('button');
        leftBtn.className = 'captcha-page-arrow';
        leftBtn.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 18l-6-6 6-6"/></svg>`;
        leftBtn.onclick = () => this.navigate(-1);

        const dotsDiv = document.createElement('div');
        dotsDiv.className = 'captcha-page-dots';

        const rightBtn = document.createElement('button');
        rightBtn.className = 'captcha-page-arrow';
        rightBtn.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>`;
        rightBtn.onclick = () => this.navigate(1);

        controls.appendChild(leftBtn);
        controls.appendChild(dotsDiv);
        controls.appendChild(rightBtn);
        scenesDiv.appendChild(controls);

        challengeArea.appendChild(referenceDiv);
        challengeArea.appendChild(scenesDiv);
        this.container.appendChild(challengeArea);

        const submitBtn = document.createElement('button');
        submitBtn.className = 'btn captcha-page-submit';
        submitBtn.textContent = this.currentRound < this.rounds.length - 1 ? 'Continue' : 'Verify';
        submitBtn.onclick = () => this.submit();
        this.container.appendChild(submitBtn);

        this.drawReference(refCanvas);
        this.drawScene(sceneCanvas);
        this.updateDots(dotsDiv);
    }

    getRoundOffset() {
        let offset = 0;
        for (let i = 0; i < this.currentRound; i++) {
            offset += 133 + this.rounds[i] * 200;
        }
        return offset;
    }

    drawReference(canvas) {
        const context = canvas.getContext('2d');
        context.clearRect(0, 0, canvas.width, canvas.height);
        context.drawImage(this.image, this.getRoundOffset(), 0, 133, 200, 0, 0, 133, 200);
    }

    drawScene(canvas) {
        const context = canvas.getContext('2d');
        context.clearRect(0, 0, canvas.width, canvas.height);
        const offset = this.getRoundOffset() + 133 + this.currentScene * 200;
        context.drawImage(this.image, offset, 0, 200, 200, 0, 0, 200, 200);
    }

    updateDots(container) {
        container.innerHTML = '';
        const count = this.rounds[this.currentRound];

        for (let i = 0; i < count; i++) {
            const dot = document.createElement('button');
            dot.className = 'captcha-page-dot' + (i === this.currentScene ? ' active' : '');
            dot.onclick = () => {
                this.currentScene = i;
                this.render();
            };
            container.appendChild(dot);
        }
    }

    navigate(direction) {
        const count = this.rounds[this.currentRound];
        this.currentScene = (this.currentScene + direction + count) % count;
        this.render();
    }

    async submit() {
        this.answers.push(this.currentScene);

        if (this.currentRound < this.rounds.length - 1) {
            this.currentRound++;
            this.currentScene = 0;
            this.render();
            return;
        }

        const submitBtn = this.container.querySelector('.captcha-page-submit');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Verifying...';

        try {
            const response = await fetch(`/api/links/${this.code}/preview/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    captcha_token: this.token,
                    captcha_answers: this.answers,
                }),
            });

            if (!response.ok) {
                const text = await response.text();
                let errorMsg = 'Verification failed';
                try {
                    const data = JSON.parse(text);
                    errorMsg = data.error || errorMsg;
                } catch {}
                throw new Error(errorMsg);
            }

            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                const data = await response.json();

                if (data.token && data.image && data.rounds) {
                    this.token = data.token;
                    this.rounds = data.rounds;
                    this.currentRound = 0;
                    this.currentScene = 0;
                    this.answers = [];
                    this.loadImage(data.image);
                    this.showError('Incorrect, please try again');
                    return;
                }
            }

            window.location.reload();
        } catch (error) {
            this.showError(error.message || 'Verification failed');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Verify';
        }
    }

    showError(message) {
        this.errorDiv.textContent = message;
        this.errorDiv.classList.add('show');
        setTimeout(() => this.errorDiv.classList.remove('show'), 3000);
    }
}

window.captchaHandler = new CaptchaHandler();
