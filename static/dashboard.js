// CYBER KAVACH // Dashboard Logic
document.addEventListener("DOMContentLoaded", () => {
    // --- Elements ---
    const modeToggle = document.getElementById("modeToggle");
    const statusIndicator = document.getElementById("statusIndicator");
    const statusText = document.getElementById("statusText");
    
    // Stats
    const statTotal = document.getElementById("statTotal");
    const statAllowed = document.getElementById("statAllowed");
    const statBlocked = document.getElementById("statBlocked");
    const statRate = document.getElementById("statRate");
    
    // Tables & Playlists
    const logsTableBody = document.getElementById("logsTableBody");
    const noTrafficRow = document.getElementById("noTrafficRow");
    const clearLogsBtn = document.getElementById("clearLogsBtn");
    
    // Search & Filters
    const filterSrcIp = document.getElementById("filterSrcIp");
    const filterDstIp = document.getElementById("filterDstIp");
    const filterProto = document.getElementById("filterProto");
    const filterPort = document.getElementById("filterPort");
    const filterAction = document.getElementById("filterAction");
    const resetFiltersBtn = document.getElementById("resetFiltersBtn");
    
    // Rules
    const rulesList = document.getElementById("rulesList");
    const addRuleToggle = document.getElementById("addRuleToggle");
    const ruleDrawer = document.getElementById("ruleDrawer");
    const addRuleForm = document.getElementById("addRuleForm");
    const cancelRuleBtn = document.getElementById("cancelRuleBtn");
    
    // Toast
    const toastNotification = document.getElementById("toastNotification");
    const toastMessage = document.getElementById("toastMessage");
    const toastClose = document.getElementById("toastClose");

    // --- State variables ---
    let totalCount = 0;
    let allowedCount = 0;
    let blockedCount = 0;
    let sseSource = null;
    let allPackets = []; // local cache buffer for live search & filtering
    
    // Threat counts for reasons chart
    const threatReasonTally = {};
    
    // Protocol counts for live throughput (reset every second)
    const activeSecondCounts = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };
    
    // --- Charts Initialization ---
    // Common Chart styling options
    const chartDefaults = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {
                    color: '#9ca3af',
                    font: { family: 'Outfit', size: 12 }
                }
            }
        }
    };

    // 1. Ratio Chart (Doughnut)
    const ratioCtx = document.getElementById("ratioChart").getContext("2d");
    const ratioChart = new Chart(ratioCtx, {
        type: 'doughnut',
        data: {
            labels: ['Allowed', 'Blocked'],
            datasets: [{
                data: [0, 0],
                backgroundColor: ['#10b981', '#ef4444'],
                borderColor: ['rgba(16, 185, 129, 0.2)', 'rgba(239, 68, 68, 0.2)'],
                borderWidth: 1
            }]
        },
        options: {
            ...chartDefaults,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#9ca3af', font: { family: 'Outfit' } }
                }
            }
        }
    });

    // 2. Block Reasons Chart (Horizontal Bar)
    const reasonCtx = document.getElementById("reasonChart").getContext("2d");
    const reasonChart = new Chart(reasonCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Blocked Packets',
                data: [],
                backgroundColor: 'rgba(239, 68, 68, 0.65)',
                borderColor: '#ef4444',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            ...chartDefaults,
            indexAxis: 'y',
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#9ca3af', stepSize: 1 }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#9ca3af', font: { family: 'Outfit' } }
                }
            }
        }
    });

    // 3. Protocol Load Chart (Line)
    const protocolCtx = document.getElementById("protocolChart").getContext("2d");
    const timeLabels = Array(20).fill(''); // 20 rolling timeline points
    const protocolChart = new Chart(protocolCtx, {
        type: 'line',
        data: {
            labels: timeLabels,
            datasets: [
                {
                    label: 'TCP',
                    data: Array(20).fill(0),
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.05)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'UDP',
                    data: Array(20).fill(0),
                    borderColor: '#8b5cf6',
                    backgroundColor: 'rgba(139, 92, 246, 0.05)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'ICMP',
                    data: Array(20).fill(0),
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.05)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            ...chartDefaults,
            scales: {
                x: { grid: { display: false }, ticks: { display: false } },
                y: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#9ca3af', font: { family: 'Outfit' } },
                    suggestedMin: 0,
                    suggestedMax: 5
                }
            }
        }
    });

    // --- Helper Functions ---
    
    // Show toast notifications for errors
    function showToast(message) {
        toastMessage.textContent = message;
        toastNotification.classList.remove("hidden");
        // Auto hide after 6 seconds
        setTimeout(() => {
            toastNotification.classList.add("hidden");
        }, 6000);
    }
    
    toastClose.addEventListener("click", () => {
        toastNotification.classList.add("hidden");
    });

    // Format numbers with animation
    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }

    // Refresh UI Stats counters
    function updateStatsUI() {
        statTotal.textContent = totalCount;
        statAllowed.textContent = allowedCount;
        statBlocked.textContent = blockedCount;
        
        const rate = totalCount > 0 ? ((blockedCount / totalCount) * 100).toFixed(1) : "0.0";
        statRate.textContent = `${rate}%`;
        
        // Update Ratio chart
        ratioChart.data.datasets[0].data = [allowedCount, blockedCount];
        ratioChart.update('none'); // Update without animation for performance
    }

    // Reset stats in UI
    function resetStats() {
        totalCount = 0;
        allowedCount = 0;
        blockedCount = 0;
        updateStatsUI();
        
        // Reset reason tally
        for (const key in threatReasonTally) delete threatReasonTally[key];
        reasonChart.data.labels = [];
        reasonChart.data.datasets[0].data = [];
        reasonChart.update();
    }

    // --- Rules Management ---

    // Load Rules from API
    async function loadRules() {
        try {
            const res = await fetch('/api/rules');
            const rules = await res.json();
            renderRules(rules);
        } catch (err) {
            console.error("Failed to load rules:", err);
            showToast("Failed to fetch rule database.");
        }
    }

    // Render Rules List
    function renderRules(rules) {
        rulesList.innerHTML = "";
        
        if (rules.length === 0) {
            rulesList.innerHTML = `
                <div class="table-placeholder">
                    <i class="fa-solid fa-circle-info"></i> No filtering rules configured.
                </div>`;
            return;
        }

        // Sort rules by priority (descending order)
        rules.sort((a, b) => (b.priority || 0) - (a.priority || 0));

        rules.forEach(rule => {
            const card = document.createElement("div");
            card.className = `rule-card ${rule.enabled ? '' : 'disabled'}`;
            card.id = `rule-card-${rule.id}`;

            const protoBadgeClass = `proto-badge ${rule.protocol.toLowerCase()}`;
            const actionClass = rule.action === 'ALLOW' ? 'badge-allow' : 'badge-block';
            const priorityBadge = `<span class="badge" style="background: rgba(139, 92, 246, 0.15); color: var(--color-purple); border: 1px solid rgba(139, 92, 246, 0.3); font-weight: 700;">Priority ${rule.priority || 0}</span>`;
            
            card.innerHTML = `
                <div class="rule-details">
                    <div class="rule-matching">
                        ${priorityBadge}
                        <span class="badge ${actionClass}">${rule.action}</span>
                        <span class="proto-badge ${rule.protocol.toLowerCase()}">${rule.protocol}</span>
                        <span class="ip-col">${rule.src_ip}:${rule.src_port}</span>
                        <span class="rule-arrow"><i class="fa-solid fa-arrow-right"></i></span>
                        <span class="ip-col">${rule.dst_ip}:${rule.dst_port}</span>
                    </div>
                    <div class="rule-reason">${rule.reason}</div>
                </div>
                <div class="rule-actions">
                    <label class="switch">
                        <input type="checkbox" class="rule-toggle-chk" data-id="${rule.id}" ${rule.enabled ? 'checked' : ''}>
                        <span class="mini-slider"></span>
                    </label>
                    <button class="delete-rule-btn" data-id="${rule.id}" title="Delete Rule">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </div>
            `;
            
            rulesList.appendChild(card);
        });

        // Attach listeners to toggles
        document.querySelectorAll(".rule-toggle-chk").forEach(chk => {
            chk.addEventListener("change", async (e) => {
                const ruleId = e.target.getAttribute("data-id");
                const enabled = e.target.checked;
                await toggleRule(ruleId, enabled);
            });
        });

        // Attach listeners to deletes
        document.querySelectorAll(".delete-rule-btn").forEach(btn => {
            btn.addEventListener("click", async (e) => {
                const ruleId = e.currentTarget.getAttribute("data-id");
                if (confirm("Are you sure you want to delete this firewall rule?")) {
                    await deleteRule(ruleId);
                }
            });
        });
    }

    // Toggle rule enable/disable state via API
    async function toggleRule(ruleId, enabled) {
        try {
            const res = await fetch(`/api/rules/${ruleId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled })
            });
            const data = await res.json();
            if (data.success) {
                const card = document.getElementById(`rule-card-${ruleId}`);
                if (enabled) {
                    card.classList.remove("disabled");
                } else {
                    card.classList.add("disabled");
                }
            } else {
                showToast(`Rule update failed: ${data.error}`);
                await loadRules(); // Reload to revert UI state
            }
        } catch (err) {
            console.error("Error toggling rule:", err);
            showToast("Failed to communicate with rule base.");
            await loadRules();
        }
    }

    // Delete rule via API
    async function deleteRule(ruleId) {
        try {
            const res = await fetch(`/api/rules/${ruleId}`, { method: 'DELETE' });
            const data = await res.json();
            if (data.success) {
                await loadRules();
            } else {
                showToast(`Failed to delete rule: ${data.error}`);
            }
        } catch (err) {
            console.error("Error deleting rule:", err);
            showToast("Failed to communicate with rule base.");
        }
    }

    // Add Rule Form Submit
    addRuleForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        
        const payload = {
            priority: parseInt(document.getElementById("priority").value) || 50,
            src_ip: document.getElementById("src_ip").value.trim(),
            dst_ip: document.getElementById("dst_ip").value.trim(),
            src_port: document.getElementById("src_port").value.trim(),
            dst_port: document.getElementById("dst_port").value.trim(),
            protocol: document.getElementById("protocol").value,
            action: document.getElementById("action").value,
            reason: document.getElementById("reason").value.trim()
        };

        try {
            const res = await fetch('/api/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (data.success) {
                addRuleForm.reset();
                // Default back to wildcard values and priority 50
                document.getElementById("src_ip").value = "*";
                document.getElementById("dst_ip").value = "*";
                document.getElementById("src_port").value = "*";
                document.getElementById("dst_port").value = "*";
                document.getElementById("priority").value = "50";
                
                ruleDrawer.classList.add("hidden");
                await loadRules();
            } else {
                showToast(`Failed to add rule: ${data.error}`);
            }
        } catch (err) {
            console.error("Error adding rule:", err);
            showToast("Failed to submit new rule.");
        }
    });

    // Drawer toggles
    addRuleToggle.addEventListener("click", () => {
        ruleDrawer.classList.toggle("hidden");
    });
    
    cancelRuleBtn.addEventListener("click", () => {
        ruleDrawer.classList.add("hidden");
    });

    // --- Packet Log Feed & Stream ---

    // Filter matching logic
    function packetMatchesFilters(packet) {
        const srcVal = filterSrcIp.value.trim().toLowerCase();
        const dstVal = filterDstIp.value.trim().toLowerCase();
        const protoVal = filterProto.value.toUpperCase();
        const portVal = filterPort.value.trim();
        const actionVal = filterAction.value.toUpperCase();

        // 1. Source IP
        if (srcVal) {
            const src = (packet.src_ip || "").toLowerCase();
            const regexSrc = new RegExp("^" + srcVal.split("*").join(".*") + "$");
            if (!src.includes(srcVal) && !regexSrc.test(src)) {
                return false;
            }
        }

        // 2. Destination IP
        if (dstVal) {
            const dst = (packet.dst_ip || "").toLowerCase();
            const regexDst = new RegExp("^" + dstVal.split("*").join(".*") + "$");
            if (!dst.includes(dstVal) && !regexDst.test(dst)) {
                return false;
            }
        }

        // 3. Protocol
        if (protoVal !== "ALL") {
            if ((packet.protocol || "").toUpperCase() !== protoVal) {
                return false;
            }
        }

        // 4. Port (matches either source or destination port)
        if (portVal) {
            const srcPort = String(packet.src_port !== null ? packet.src_port : "");
            const dstPort = String(packet.dst_port !== null ? packet.dst_port : "");
            if (srcPort !== portVal && dstPort !== portVal) {
                return false;
            }
        }

        // 5. Action
        if (actionVal !== "ALL") {
            if ((packet.action || "").toUpperCase() !== actionVal) {
                return false;
            }
        }

        return true;
    }

    // Apply active filters to the cache and rebuild DOM
    function applyFilters() {
        logsTableBody.innerHTML = "";
        const matches = allPackets.filter(packetMatchesFilters);

        if (matches.length === 0) {
            logsTableBody.appendChild(noTrafficRow);
            noTrafficRow.style.display = "";
            noTrafficRow.querySelector("td").innerHTML = `<i class="fa-solid fa-circle-info"></i> No packets match active filters.`;
        } else {
            noTrafficRow.style.display = "none";
            // Prepending loop: looping chronologically places the newest at the top
            matches.forEach(pkt => {
                appendPacketRowDirect(pkt);
            });
        }
    }

    // Direct appender without duplicate filter evaluation
    function appendPacketRowDirect(packet) {
        if (noTrafficRow) {
            noTrafficRow.style.display = "none";
        }

        const tr = document.createElement("tr");
        const isBlocked = packet.action === "BLOCK";
        tr.className = `packet-row ${isBlocked ? 'row-block' : 'row-allow'}`;
        
        const packetIdHTML = `<span style="font-weight: 600; color: var(--text-secondary); display: block; font-size: 11px; margin-bottom: 2px;">Packet #${packet.id || 'N/A'}</span>`;
        const statusBadge = isBlocked 
            ? `<span class="badge badge-block">BLOCKED</span>` 
            : `<span class="badge badge-allow">ALLOWED</span>`;
            
        const srcPortText = packet.src_port !== null ? `:${packet.src_port}` : '';
        const dstPortText = packet.dst_port !== null ? `:${packet.dst_port}` : '';
        
        const reasonHTML = `<span class="reason-line" style="display: block; font-size: 11px; margin-top: 4px;">Reason: ${packet.reason || 'N/A'}</span>`;

        tr.innerHTML = `
            <td>${packet.timestamp}</td>
            <td><span class="proto-badge ${packet.protocol.toLowerCase()}">${packet.protocol}</span></td>
            <td>
                <span class="ip-col">${packet.src_ip}</span><span class="port-col">${srcPortText}</span>
            </td>
            <td>
                <span class="ip-col">${packet.dst_ip}</span><span class="port-col">${dstPortText}</span>
            </td>
            <td>
                ${packetIdHTML}
                ${statusBadge}
                ${reasonHTML}
            </td>
            <td style="color: var(--text-secondary);">${packet.length} B</td>
        `;

        tr.style.cursor = "pointer";
        tr.addEventListener("click", () => {
            showPacketDetails(packet);
        });

        logsTableBody.insertBefore(tr, logsTableBody.firstChild);

        if (logsTableBody.children.length > 51) {
            logsTableBody.removeChild(logsTableBody.lastChild);
        }
    }

    // Add row to traffic table
    function appendPacketRow(packet) {
        appendPacketRowDirect(packet);
    }

    // Wireshark Packet Inspector Logic
    const packetDrawer = document.getElementById("packetDrawer");
    const closePacketDrawer = document.getElementById("closePacketDrawer");

    closePacketDrawer.addEventListener("click", () => {
        packetDrawer.classList.add("hidden");
    });

    // Toggle collapsible inspector sections
    document.querySelectorAll(".inspector-title").forEach(title => {
        title.addEventListener("click", () => {
            title.parentElement.classList.toggle("collapsed");
        });
    });

    function showPacketDetails(packet) {
        document.getElementById("inspectId").textContent = packet.id || 'N/A';
        document.getElementById("inspectTime").textContent = packet.timestamp || 'N/A';
        document.getElementById("inspectLen").textContent = (packet.length || 0) + ' bytes';
        document.getElementById("inspectAction").innerHTML = packet.action === 'BLOCK' 
            ? `<span class="badge badge-block">BLOCKED</span>` 
            : `<span class="badge badge-allow">ALLOWED</span>`;

        document.getElementById("inspectSrcIP").textContent = packet.src_ip || 'N/A';
        document.getElementById("inspectDstIP").textContent = packet.dst_ip || 'N/A';
        document.getElementById("inspectTTL").textContent = packet.ttl || 'N/A';
        
        const protoBadge = document.getElementById("inspectProtocol");
        protoBadge.textContent = packet.protocol || 'N/A';
        protoBadge.className = `proto-badge ${packet.protocol ? packet.protocol.toLowerCase() : ''}`;

        // Layer 4 TCP/UDP Details
        const layer4Sec = document.getElementById("layer4Sec");
        const layer4Title = document.getElementById("layer4Title");
        
        if (packet.protocol === 'TCP' || packet.protocol === 'UDP') {
            layer4Sec.style.display = '';
            document.getElementById("inspectSrcPort").textContent = packet.src_port || 'N/A';
            document.getElementById("inspectDstPort").textContent = packet.dst_port || 'N/A';
            
            if (packet.protocol === 'TCP') {
                layer4Title.innerHTML = `<i class="fa-solid fa-caret-down"></i> Transmission Control Protocol (TCP)`;
                document.getElementById("flagsRow").style.display = '';
                document.getElementById("inspectFlags").textContent = packet.flags || 'N/A';
            } else {
                layer4Title.innerHTML = `<i class="fa-solid fa-caret-down"></i> User Datagram Protocol (UDP)`;
                document.getElementById("flagsRow").style.display = 'none';
            }
        } else {
            // Hide TCP/UDP layer for ICMP or raw protocols
            layer4Sec.style.display = 'none';
        }

        // Sentry Verdict details
        document.getElementById("inspectMatchedRule").textContent = packet.rule_id || 'Default Policy';
        document.getElementById("inspectVerdict").innerHTML = packet.action === 'BLOCK'
            ? `<span class="badge badge-block">BLOCK (REJECTED)</span>`
            : `<span class="badge badge-allow">ALLOW (FORWARDED)</span>`;
            
        const inspectReason = document.getElementById("inspectReason");
        inspectReason.textContent = packet.reason || 'N/A';
        if (packet.action === 'BLOCK') {
            inspectReason.style.color = 'var(--color-danger)';
        } else {
            inspectReason.style.color = 'var(--color-success)';
        }

        // Hex Dump
        document.getElementById("inspectHexDump").textContent = packet.payload_hex || 'No payload data';

        // Slide Open Drawer
        packetDrawer.classList.remove("hidden");
    }

    // Process an incoming packet
    function handleIncomingPacket(packet) {
        // Cache globally (limit to 500 history elements to prevent browser memory leaks)
        allPackets.push(packet);
        if (allPackets.length > 500) {
            allPackets.shift();
        }

        totalCount++;
        if (packet.action === "ALLOW") {
            allowedCount++;
        } else {
            blockedCount++;
            // Increment reason tally
            const reason = packet.reason || "Rule violation";
            threatReasonTally[reason] = (threatReasonTally[reason] || 0) + 1;
            updateReasonsChart();
        }

        // Tally for protocol throughput
        const proto = packet.protocol.toUpperCase();
        if (activeSecondCounts.hasOwnProperty(proto)) {
            activeSecondCounts[proto]++;
        } else {
            activeSecondCounts.OTHER++;
        }

        // Append to DOM list only if it satisfies search filters
        if (packetMatchesFilters(packet)) {
            appendPacketRow(packet);
        }
        
        // Update stats
        updateStatsUI();
    }

    // Update Threat Reasons Chart
    function updateReasonsChart() {
        const sortedReasons = Object.entries(threatReasonTally)
            .sort((a, b) => b[1] - a[1]) // Sort descending
            .slice(0, 5); // Take top 5

        reasonChart.data.labels = sortedReasons.map(item => item[0]);
        reasonChart.data.datasets[0].data = sortedReasons.map(item => item[1]);
        reasonChart.update('none'); // Update without bounce for smoother visuals
    }

    // Clear Stream Logs
    clearLogsBtn.addEventListener("click", async () => {
        try {
            const res = await fetch('/api/logs/clear', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                allPackets = []; // Clear local cache list
                logsTableBody.innerHTML = "";
                noTrafficRow.querySelector("td").innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Awaiting packet transmissions...`;
                noTrafficRow.style.display = "";
                logsTableBody.appendChild(noTrafficRow);
                resetStats();
            }
        } catch (err) {
            console.error("Error clearing logs:", err);
            showToast("Failed to clear historical logs.");
        }
    });

    // Filter event listeners to handle typing & selections
    [filterSrcIp, filterDstIp, filterPort].forEach(el => {
        el.addEventListener("input", applyFilters);
    });

    [filterProto, filterAction].forEach(el => {
        el.addEventListener("change", applyFilters);
    });

    resetFiltersBtn.addEventListener("click", () => {
        filterSrcIp.value = "";
        filterDstIp.value = "";
        filterProto.value = "ALL";
        filterPort.value = "";
        filterAction.value = "ALL";
        noTrafficRow.querySelector("td").innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Awaiting packet transmissions...`;
        applyFilters();
    });

    // Populate log ticker with backend buffer
    async function loadRecentLogs() {
        try {
            const res = await fetch('/api/logs');
            const logs = await res.json();
            
            // Loop chronologically to populate counts and graphs correctly
            logs.forEach(pkt => {
                handleIncomingPacket(pkt);
            });
        } catch (err) {
            console.error("Error loading recent logs:", err);
        }
    }

    // --- Real-time Connection & SSE Stream ---

    function startSSEStream() {
        if (sseSource) {
            sseSource.close();
        }

        sseSource = new EventSource('/api/stream');

        sseSource.onmessage = (event) => {
            const packet = JSON.parse(event.data);
            handleIncomingPacket(packet);
        };

        sseSource.addEventListener("ping", (event) => {
            // Keep-alive or verification ping
            console.log("SSE Stream connected.");
            updateStatusText();
        });

        sseSource.onerror = (err) => {
            console.error("SSE stream error:", err);
            statusIndicator.className = "status-indicator offline";
            statusText.textContent = "Reconnecting...";
            // Browser automatically tries to reconnect SSE, but we close and restart to be safe after delay
            setTimeout(startSSEStream, 5000);
        };
    }

    // Update the UI Connection status based on mode & errors
    async function updateStatusText() {
        try {
            const res = await fetch('/api/status');
            const status = await res.json();
            
            // Check checkbox status matches backend
            modeToggle.checked = (status.mode === "live");
            
            if (status.mode === "live") {
                if (status.error) {
                    // Warning status: Live failed and fell back
                    statusIndicator.className = "status-indicator warning";
                    statusText.textContent = "Live Failed (Simulating)";
                    showToast(status.error);
                } else {
                    statusIndicator.className = "status-indicator online";
                    statusText.textContent = "Live Capturing";
                }
            } else {
                statusIndicator.className = "status-indicator online";
                statusText.textContent = "Simulating Traffic";
            }
        } catch (err) {
            console.error("Failed to query status:", err);
            statusIndicator.className = "status-indicator offline";
            statusText.textContent = "Offline";
        }
    }

    // Toggle Mode Change Handler
    modeToggle.addEventListener("change", async (e) => {
        const targetMode = e.target.checked ? "live" : "simulation";
        statusIndicator.className = "status-indicator warning";
        statusText.textContent = "Switching...";
        
        try {
            const res = await fetch('/api/toggle_mode', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: targetMode })
            });
            const data = await res.json();
            
            if (!data.success) {
                // If it failed (e.g. Scapy failed on Windows), display toast error
                showToast(data.message || "Failed to switch mode.");
            }
            
            // Sync status
            await updateStatusText();
        } catch (err) {
            console.error("Error toggling mode:", err);
            showToast("Failed to switch mode. Backend communication error.");
            await updateStatusText();
        }
    });

    // --- Line Chart Throughput Ticker (Ticking every 1 second) ---
    setInterval(() => {
        // Shift data array
        const datasets = protocolChart.data.datasets;
        
        // TCP
        datasets[0].data.push(activeSecondCounts.TCP);
        datasets[0].data.shift();
        
        // UDP
        datasets[1].data.push(activeSecondCounts.UDP);
        datasets[1].data.shift();
        
        // ICMP
        datasets[2].data.push(activeSecondCounts.ICMP);
        datasets[2].data.shift();
        
        // Update Chart
        protocolChart.update('none');

        // Reset counts for the next second duration
        activeSecondCounts.TCP = 0;
        activeSecondCounts.UDP = 0;
        activeSecondCounts.ICMP = 0;
        activeSecondCounts.OTHER = 0;
    }, 1000);

    // Initial setups
    loadRules();
    loadRecentLogs().then(() => {
        startSSEStream();
        updateStatusText();
    });

    // Periodically poll status to sync connection indicator
    setInterval(updateStatusText, 10000);
});
