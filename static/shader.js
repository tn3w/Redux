const canvas = document.getElementById('canvas');
const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

if (!gl) {
    canvas.style.background = 'radial-gradient(ellipse at center, #1a1a1a 0%, #000 70%)';
    canvas.style.opacity = '0.8';
} else {
    initShader();
}

function initShader() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const vertexShader = `
        attribute vec4 aVertexPosition;
        void main() { gl_Position = aVertexPosition; }
    `;

    const fragmentShader = `
        precision highp float;
        uniform vec2 resolution;
        uniform float time;
        void main() {
            vec2 r = resolution;
            vec2 FC = gl_FragCoord.xy;
            float t = time;
            vec2 p = (FC * 2.0 - r) / r.y / 0.7;
            vec2 d = vec2(-1.0, 1.0);
            vec2 c = p * mat2(1.0, 1.0, d / (0.1 + 5.0 / 
                dot(5.0 * p - d, 5.0 * p - d)));
            vec2 v = c;
            v *= mat2(cos(log(length(v)) + t * 0.2 + 
                vec4(0, 33, 11, 0))) * 5.0;
            vec4 o = vec4(0.0);
            for (float i = 0.0; i < 9.0; i += 1.0) {
                o += sin(v.xyyx) + 1.0;
                v += 0.7 * sin(v.yx * (i + 1.0) + t) / (i + 1.0) + 0.5;
            }
            vec4 color = vec4(1.0) - exp(-exp(c.x * 
                vec4(0.6, -0.4, -1.0, 0.0)) / o / 
                (0.1 + 0.1 * pow(length(sin(v / 0.3) * 0.2 + c * 
                vec2(1.0, 2.0)) - 1.0, 2.0)) / 
                (1.0 + 7.0 * exp(0.3 * c.y - dot(c, c))) / 
                (0.03 + abs(length(p) - 0.7)) * 0.2);
            float brightness = max(max(color.r, color.g), color.b);
            brightness = brightness * 0.6;
            gl_FragColor = vec4(vec3(brightness), 1.0);
        }
    `;

    const vs = loadShader(gl.VERTEX_SHADER, vertexShader);
    const fs = loadShader(gl.FRAGMENT_SHADER, fragmentShader);

    if (!vs || !fs) {
        canvas.style.background = 'radial-gradient(ellipse at center, #1a1a1a 0%, #000 70%)';
        canvas.style.opacity = '0.8';
        return;
    }

    const program = gl.createProgram();
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);

    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
        console.error('Program linking error:', gl.getProgramInfoLog(program));
        return;
    }

    const positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, 1, 1, 1, -1, -1, 1, -1]), gl.STATIC_DRAW);

    const positionLocation = gl.getAttribLocation(program, 'aVertexPosition');
    const resolutionLocation = gl.getUniformLocation(program, 'resolution');
    const timeLocation = gl.getUniformLocation(program, 'time');

    const startTime = Date.now();

    function render() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        gl.viewport(0, 0, canvas.width, canvas.height);
        gl.useProgram(program);
        gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
        gl.vertexAttribPointer(positionLocation, 2, gl.FLOAT, false, 0, 0);
        gl.enableVertexAttribArray(positionLocation);
        gl.uniform2f(resolutionLocation, canvas.width, canvas.height);
        gl.uniform1f(timeLocation, (Date.now() - startTime) * 0.001);
        gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
        requestAnimationFrame(render);
    }
    render();
}

function loadShader(type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);

    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
        console.error('Shader compilation error:', gl.getShaderInfoLog(shader));
        gl.deleteShader(shader);
        return null;
    }
    return shader;
}

window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});
