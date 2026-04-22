// Build script for the password-gated Mother's Day site.
//
// Reads plaintext HTML from src/, inlines local images under images/ as
// base64 data URIs, encrypts each file with a password-derived AES-GCM key,
// and writes the encrypted wrapper HTML to the committed public paths.
//
// Usage:
//   node scripts/build.mjs
//   PASSWORD="new-password" node scripts/build.mjs   (rotate password)
//
// No npm deps — uses only Node 18+ stdlib (globalThis.crypto.subtle).

import { readFile, writeFile, readdir, mkdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

var HERE = path.dirname(fileURLToPath(import.meta.url))
var ROOT = path.resolve(HERE, '..')
var SRC = path.join(ROOT, 'src')
var IMAGES = path.join(ROOT, 'images')
var TEMPLATE_PATH = path.join(HERE, 'wrapper-template.html')

var PASSWORD = process.env.PASSWORD || 'tinalovesphotography11'
var PBKDF2_ITER = 600000

// Matches any literal ../images/FILENAME.ext where ext is an image type.
// Anchored so data: URIs and remote URLs are never touched.
var IMG_REF = /(\.\.\/images\/)([A-Za-z0-9._-]+\.(?:jpe?g|png|gif|webp|avif))/g

// Pure: maps a filename extension to its MIME type. Returns undefined if unknown.
function mimeFor (filename) {
  var ext = path.extname(filename).slice(1).toLowerCase()
  var map = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg',
    png: 'image/png', gif: 'image/gif',
    webp: 'image/webp', avif: 'image/avif'
  }
  return map[ext]
}

// Pure helper: Uint8Array -> base64 string.
function b64 (u8) {
  return Buffer.from(u8).toString('base64')
}

// Side effect: reads images from disk. Returns a new HTML string with
// every ../images/FILE.ext reference replaced by a data: URI.
async function inlineImages (html) {
  var refs = new Set()
  html.replace(IMG_REF, function (_m, _prefix, fn) {
    refs.add(fn)
    return _m
  })
  var cache = new Map()
  await Promise.all([...refs].map(async function (fn) {
    var buf = await readFile(path.join(IMAGES, fn))
    var mime = mimeFor(fn)
    if (!mime) throw new Error('Unknown image type: ' + fn)
    cache.set(fn, 'data:' + mime + ';base64,' + buf.toString('base64'))
  }))
  return html.replace(IMG_REF, function (_m, _prefix, fn) {
    return cache.get(fn)
  })
}

// Side effect: runs PBKDF2 + AES-GCM encryption via Web Crypto.
// Pure in effect — returns { v, iter, salt, iv, ct } with base64 strings.
async function encryptHtml (plaintext, password) {
  var salt = crypto.getRandomValues(new Uint8Array(16))
  var iv = crypto.getRandomValues(new Uint8Array(12))
  var base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password),
    'PBKDF2', false, ['deriveKey']
  )
  var key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  )
  var ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    new TextEncoder().encode(plaintext)
  )
  return {
    v: 1,
    iter: PBKDF2_ITER,
    salt: b64(salt),
    iv: b64(iv),
    ct: b64(new Uint8Array(ct))
  }
}

// Pure: substitutes the encrypted payload JSON into the wrapper template.
function wrap (template, encrypted) {
  var json = JSON.stringify(encrypted)
  return template.replace('{{PAYLOAD_JSON}}', json)
}

// Side effect: builds one source file -> encrypted wrapper at outPath.
async function buildFile (srcPath, outPath, template) {
  var html = await readFile(srcPath, 'utf8')
  var inlined = await inlineImages(html)
  var encrypted = await encryptHtml(inlined, PASSWORD)
  var wrapped = wrap(template, encrypted)
  await mkdir(path.dirname(outPath), { recursive: true })
  await writeFile(outPath, wrapped)
  var kb = Math.round(wrapped.length / 1024)
  console.log('wrote', path.relative(ROOT, outPath), '(' + kb + ' KB)')
}

// Side effect: orchestrates the whole build.
async function main () {
  var template = await readFile(TEMPLATE_PATH, 'utf8')
  console.log('building with password of length', PASSWORD.length,
              '(' + PBKDF2_ITER + ' PBKDF2 iter)')

  // Root redirect page.
  await buildFile(
    path.join(SRC, 'index.html'),
    path.join(ROOT, 'index.html'),
    template
  )

  // Prototypes.
  var dir = path.join(SRC, 'prototyping')
  var files = (await readdir(dir)).filter(function (f) {
    return f.endsWith('.html')
  })
  for (var i = 0; i < files.length; i++) {
    var f = files[i]
    await buildFile(
      path.join(dir, f),
      path.join(ROOT, 'prototyping', f),
      template
    )
  }

  console.log('done.')
}

main().catch(function (e) {
  console.error(e)
  process.exit(1)
})
