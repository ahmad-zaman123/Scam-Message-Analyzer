// Client-side OCR, loaded lazily. tesseract.js reads text from a screenshot and
// jsQR decodes any QR code ("quishing"). Both are fetched from a CDN only when
// the user first uploads an image; the image is processed in the browser and is
// never uploaded anywhere.

const TESSERACT_URL = "https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js";
const JSQR_URL = "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js";

const scriptCache = {};
function loadScript(url) {
  if (!scriptCache[url]) {
    scriptCache[url] = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = url;
      s.onload = () => resolve();
      s.onerror = () => reject(new Error("Could not load " + url));
      document.head.appendChild(s);
    });
  }
  return scriptCache[url];
}

async function decodeQrUrl(file) {
  try {
    await loadScript(JSQR_URL);
    const bitmap = await createImageBitmap(file);
    const canvas = document.createElement("canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(bitmap, 0, 0);
    const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = window.jsQR(image.data, image.width, image.height);
    if (code && /^https?:\/\//i.test(code.data)) return code.data.trim();
  } catch (e) {
    // QR support is a bonus — ignore failures.
  }
  return null;
}

/** Extract text from an image File/Blob. onProgress(0..1) reports OCR progress. */
export async function imageToText(file, onProgress) {
  await loadScript(TESSERACT_URL);
  const result = await window.Tesseract.recognize(file, "eng", {
    logger: (m) => {
      if (onProgress && m.status === "recognizing text") onProgress(m.progress);
    },
  });
  let text = (result.data.text || "").trim();
  const qrUrl = await decodeQrUrl(file);
  if (qrUrl) text += "\nLink from QR code: " + qrUrl;
  return text;
}
