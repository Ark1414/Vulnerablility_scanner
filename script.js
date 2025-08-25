async function scanWebsite() {
  const url = document.getElementById("urlInput").value;
  const scanBtn = document.getElementById("scanBtn");
  const loader = document.getElementById("loader");

  scanBtn.disabled = true;
  loader.style.display = "block";

  try {
    const response = await fetch("http://localhost:8000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Scan failed");
    }

    const result = await response.json();
    displayScanResults(result);
    addToHistory(result);

  } catch (error) {
    alert("Error: " + error.message);
  } finally {
    scanBtn.disabled = false;
    loader.style.display = "none";
  }
}

function displayScanResults(data) {
  document.getElementById("riskLevel").innerText = `Risk Level: ${data.risk_level}`;
  document.getElementById("tips").innerHTML = data.tips.map(tip => `<li>${tip}</li>`).join("");
  renderBarChart(data.vulnerabilities);
  renderPieChart(data.risk_level);
}

function addToHistory(data) {
  const historyDiv = document.getElementById("scanHistory");
  const entry = document.createElement("div");
  entry.className = "log-entry";
  entry.innerHTML = `<strong>${data.url}</strong><br>Risk: ${data.risk_level}`;
  historyDiv.prepend(entry);
}

function renderBarChart(vulnerabilities) {
  d3.select("#barChart").html("");

  const data = vulnerabilities.map(v => ({ type: v.type, count: v.count }));
  const width = 300;
  const height = 300;
  const margin = { top: 20, right: 20, bottom: 40, left: 40 };

  const svg = d3.select("#barChart")
    .append("svg")
    .attr("width", width)
    .attr("height", height);

  const x = d3.scaleBand()
    .domain(data.map(d => d.type))
    .range([margin.left, width - margin.right])
    .padding(0.3);

  const y = d3.scaleLinear()
    .domain([0, d3.max(data, d => d.count)])
    .nice()
    .range([height - margin.bottom, margin.top]);

  svg.selectAll("rect")
    .data(data)
    .enter()
    .append("rect")
    .attr("x", d => x(d.type))
    .attr("y", d => y(d.count))
    .attr("height", d => y(0) - y(d.count))
    .attr("width", x.bandwidth())
    .attr("fill", "#3b82f6");

  svg.append("g")
    .attr("transform", `translate(0,${height - margin.bottom})`)
    .call(d3.axisBottom(x));

  svg.append("g")
    .attr("transform", `translate(${margin.left},0)`)
    .call(d3.axisLeft(y));
}

function renderPieChart(riskLevel) {
  d3.select("#pieChart").html("");

  const levels = ["Low", "Medium", "High"];
  const data = levels.map(level => ({
    label: level,
    value: level === riskLevel ? 1 : 0.01
  }));

  const width = 300;
  const height = 300;
  const radius = Math.min(width, height) / 2;

  const svg = d3.select("#pieChart")
    .append("svg")
    .attr("width", width)
    .attr("height", height)
    .append("g")
    .attr("transform", `translate(${width / 2}, ${height / 2})`);

  const arc = d3.arc().innerRadius(0).outerRadius(radius);
  const pie = d3.pie().value(d => d.value);

  const color = d3.scaleOrdinal()
    .domain(levels)
    .range(["#22c55e", "#facc15", "#ef4444"]);

  svg.selectAll("path")
    .data(pie(data))
    .enter()
    .append("path")
    .attr("d", arc)
    .attr("fill", d => color(d.data.label))
    .append("title")
    .text(d => d.data.label);
}
window.onload = () => {
  loadScanHistory();
};

async function loadScanHistory() {
  try {
    const response = await fetch("http://localhost:8000/history");
    const data = await response.json();
    data.history.forEach(addToHistory);
  } catch (err) {
    console.error("Failed to load history:", err);
  }
}

function displayScanResults(data) {
  document.getElementById("riskLevel").innerText = `Risk Level: ${data.risk_level}`;
  document.getElementById("tips").innerHTML = data.tips.map(tip => `<li>${tip}</li>`).join("");

  const vulnList = data.vulnerabilities.map(v => {
    let detailsText = "";
    if (v.details && v.details.length > 0) {
      detailsText = `: ${v.details.join(", ")}`;
    }
    return `<li><strong>${v.type}</strong>${detailsText}</li>`;
  }).join("");

  document.getElementById("vulnerabilities").innerHTML = `
    <h3>Vulnerabilities Found</h3>
    <ul>${vulnList}</ul>
  `;

  renderBarChart(data.vulnerabilities);
  renderPieChart(data.risk_level);
}

