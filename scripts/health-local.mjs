import http from "node:http";

const checks = [
  {
    name: "public-site",
    url: "http://127.0.0.1:3000",
    expectedStatus: 200
  },
  {
    name: "hub health",
    url: "http://127.0.0.1:3001/api/health",
    expectedStatus: 200
  }
];

function requestStatus(url) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, { timeout: 5000 }, response => {
      response.resume();
      response.on("end", () => resolve(response.statusCode));
    });

    request.on("timeout", () => {
      request.destroy(new Error("request timed out"));
    });

    request.on("error", reject);
  });
}

async function checkEndpoint(check) {
  try {
    const statusCode = await requestStatus(check.url);

    if (statusCode === check.expectedStatus) {
      console.log(`PASS ${check.name}: ${check.url} returned ${statusCode}`);
      return true;
    }

    console.error(
      `FAIL ${check.name}: ${check.url} returned ${statusCode}, expected ${check.expectedStatus}`
    );
    return false;
  } catch (error) {
    console.error(`FAIL ${check.name}: ${check.url} failed (${error.message})`);
    return false;
  }
}

const results = await Promise.all(checks.map(checkEndpoint));

if (results.every(Boolean)) {
  console.log("Local BielOS health checks passed.");
  process.exit(0);
}

console.error("One or more local BielOS health checks failed.");
process.exit(1);
