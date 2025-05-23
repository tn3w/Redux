/* eslint-disable */
/**
 * Build script for Redux URL Shortener
 * Minifies templates and embeds CSS/JS content
 */

const fs = require('fs-extra');
const path = require('path');
const cheerio = require('cheerio');
const { minify } = require('terser');
const CleanCSS = require('clean-css');

const TEMPLATES_DIR = path.join(__dirname, 'templates');
const BUILD_DIR = path.join(__dirname, 'build');

fs.ensureDirSync(BUILD_DIR);

const cleanCSS = new CleanCSS({
    level: {
        1: { specialComments: 0 },
        2: { restructureRules: true },
    },
});

async function processTemplates() {
    const templateFiles = fs.readdirSync(TEMPLATES_DIR).filter((file) => file.endsWith('.html'));

    console.log(`Found ${templateFiles.length} template(s) to process`);

    for (const templateFile of templateFiles) {
        const templatePath = path.join(TEMPLATES_DIR, templateFile);
        const html = fs.readFileSync(templatePath, 'utf8');
        const $ = cheerio.load(html, { decodeEntities: false });

        console.log(`Processing ${templateFile}...`);

        $('link[rel="stylesheet"]').each(function () {
            const href = $(this).attr('href');
            if (href && href.startsWith('static/')) {
                const cssPath = path.join(__dirname, href);
                if (fs.existsSync(cssPath)) {
                    const cssContent = fs.readFileSync(cssPath, 'utf8');
                    const minifiedCSS = cleanCSS.minify(cssContent).styles;
                    $(this).replaceWith(`<style>${minifiedCSS}</style>`);
                    console.log(`Embedded and minified CSS from ${href}`);
                } else {
                    console.warn(`CSS file not found: ${cssPath}`);
                }
            }
        });

        const promises = [];
        $('script').each(function () {
            const src = $(this).attr('src');
            if (src && src.startsWith('static/')) {
                const jsPath = path.join(__dirname, src);
                if (fs.existsSync(jsPath)) {
                    const jsContent = fs.readFileSync(jsPath, 'utf8');
                    const element = $(this);

                    const promise = minify(jsContent, {
                        compress: {
                            drop_console: true,
                            drop_debugger: true,
                        },
                        mangle: true,
                    })
                        .then((result) => {
                            element.removeAttr('src');
                            element.text(result.code);
                            console.log(`Embedded and minified JS from ${src}`);
                        })
                        .catch((err) => {
                            console.error(`Error minifying ${src}: ${err.message}`);
                        });

                    promises.push(promise);
                } else {
                    console.warn(`JS file not found: ${jsPath}`);
                }
            }
        });

        await Promise.all(promises);

        const minifiedHtml = $.html()
            .replace(/^\s*\n/gm, '')
            .replace(/\s{2,}/g, ' ')
            .replace(/>\s+</g, '><')
            .replace(/<!--(?!<!)[^\[>].*?-->/g, '')
            .trim();

        const outputPath = path.join(BUILD_DIR, templateFile);
        fs.writeFileSync(outputPath, minifiedHtml);

        console.log(`Successfully minified ${templateFile} -> ${outputPath}`);
    }
}

async function build() {
    console.log('Starting build process...');

    try {
        await processTemplates();
        console.log('Build completed successfully!');
    } catch (error) {
        console.error(`Build failed: ${error.message}`);
        process.exit(1);
    }
}

build();
