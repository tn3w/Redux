<p align="center">
	<a href="https://github.com/tn3w/Redux">
		<picture>
			<source width="800px" media="(prefers-color-scheme: dark)" srcset="https://github.com/tn3w/Redux/releases/download/img/redux-dark.webp">
			<source width="800px" media="(prefers-color-scheme: light)" srcset="https://github.com/tn3w/Redux/releases/download/img/redux-light.webp">
			<img width="800px" alt="Redux Screenshot" src="https://github.com/tn3w/Redux/releases/download/img/redux-dark.webp">
		</picture>
	</a>
</p>

<h1 align="center">Redux</h1>
<p align="center">A secure link shortener PWA that allows users to create and manage links, with optional end-to-end encryption for enhanced privacy.</p>

## ToDo
- [x] Modify the behavior of the info button on the My Links page so that clicking it updates the URL in the address bar to /#id (where id is the identifier of the URL) instead of #info-page and ensure that when users click the "Back" button or navigate back, they are returned to the My Links page instead of the home page.
- [x] Implement logic to display the clear button only when the form contains input content.
- [x] Enhance the displayUrlInfo function by adding a click handler to the "Visit URL" button, which will show users the appropriate redirection page instead of showing the home page and going to /#.

## Installation
1. **Clone this repository**:
   ```bash
   git clone https://github.com/tn3w/Redux.git
   cd Redux
   ```
2. **Create an virtual environment and install dependencies**:
    ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. **Run Redux**:
    ```bash
    python app.py
    ```
