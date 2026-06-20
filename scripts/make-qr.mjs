import QRCode from "qrcode";

const url = process.argv[2];
if (!url) {
  console.error("Usage: npm run qr -- https://interview-lock.<you>.workers.dev/");
  process.exit(1);
}

// Print a scannable QR straight to the terminal...
QRCode.toString(url, { type: "terminal", small: true }).then((s) => {
  console.log(s);
  console.log("URL:", url);
});

// ...and save a high-res PNG to print and tape on the wall.
QRCode.toFile("interview-qr.png", url, { width: 800, margin: 2 }).then(() => {
  console.log("Saved interview-qr.png");
});
