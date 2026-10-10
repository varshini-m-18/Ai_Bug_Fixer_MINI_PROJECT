// AI Bug Fixer Web Prototype Client - Multi-Language Enabled
document.addEventListener('DOMContentLoaded', () => {
  // State
  let presets = [];
  let currentPreset = null;
  let currentLanguage = 'javascript';
  let currentStep = 1;
  let buggyCode = '';
  let fixedCode = '';
  let detectedFindings = [];
  let selectedFinding = null;
  let rootCauseData = null;
  let isDiffMode = false;

  // DOM Elements
  const codeEditor = document.getElementById('code-editor');
  const lineNumbers = document.getElementById('line-numbers');
  const languageSelect = document.getElementById('language-select');
  const presetSelect = document.getElementById('preset-select');
  const editorTitle = document.getElementById('editor-title');
  const editorBadge = document.getElementById('editor-badge');
  const editorMeta = document.getElementById('editor-meta');
  const btnRunFullFlow = document.getElementById('btn-run-full-flow');
  const btnRunCode = document.getElementById('btn-run-code');
  const btnResetCode = document.getElementById('btn-reset-code');
  const btnToggleDiff = document.getElementById('btn-toggle-diff');
  const btnApplyFix = document.getElementById('btn-apply-fix');
  const editorViewMode = document.getElementById('editor-view-mode');
  const diffViewMode = document.getElementById('diff-view-mode');
  const diffOriginalCode = document.getElementById('diff-original-code');
  const diffFixedCode = document.getElementById('diff-fixed-code');
  const stepProgressBar = document.getElementById('step-progress-bar');
  const systemStatus = document.getElementById('system-status');

  // Terminal elements
  const terminalOutput = document.getElementById('terminal-output');
  const terminalMeta = document.getElementById('terminal-meta');
  const terminalBadge = document.getElementById('terminal-badge');

  // Findings elements
  const findingsContainer = document.getElementById('findings-container');
  const findingsSummary = document.getElementById('findings-summary');
  const detectBadge = document.getElementById('detect-badge');
  const btnReDetect = document.getElementById('btn-re-detect');

  // Cause elements
  const causeContainer = document.getElementById('cause-container');

  // Fix elements
  const fixOverview = document.getElementById('fix-overview');

  // Verification elements
  const verificationContainer = document.getElementById('verification-container');
  const verifyBadge = document.getElementById('verify-badge');

  // Next-step action buttons
  const btnActionStep2 = document.getElementById('btn-action-step2');
  const btnActionStep3 = document.getElementById('btn-action-step3');
  const btnActionStep4 = document.getElementById('btn-action-step4');
  const btnActionStep5 = document.getElementById('btn-action-step5');
  const btnActionStep6 = document.getElementById('btn-action-step6');
  const btnActionStep7 = document.getElementById('btn-action-step7');

  if (systemStatus) {
    systemStatus.innerHTML = '<span class="status-indicator"></span><span>Multi-Lang Engine Active (JS, Py, Java, C, C++)</span>';
  }

  // Toast Notification
  function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  // Update Line Numbers & Character Count
  function updateEditorMetrics() {
    const text = codeEditor.value;
    const lines = text.split('\n').length;
    lineNumbers.textContent = Array.from({ length: lines }, (_, i) => i + 1).join('\n');
    editorMeta.textContent = `Lang: ${currentLanguage.toUpperCase()} | Lines: ${lines} | Chars: ${text.length}`;
  }

  codeEditor.addEventListener('input', () => {
    updateEditorMetrics();
    editorBadge.textContent = 'Modified';
    editorBadge.className = 'badge info';
  });

  codeEditor.addEventListener('scroll', () => {
    lineNumbers.scrollTop = codeEditor.scrollTop;
  });

  // Tab Switching
  const tabs = document.querySelectorAll('.tab-btn');
  const contents = document.querySelectorAll('.inspector-content');

  function switchTab(tabId) {
    tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
    contents.forEach(c => c.classList.toggle('hidden', c.id !== `content-${tabId}`));
  }

  tabs.forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  // Step Indicator Navigation
  function setStep(stepNum) {
    currentStep = stepNum;
    for (let i = 1; i <= 7; i++) {
      const stepBtn = document.getElementById(`step-btn-${i}`);
      if (!stepBtn) continue;
      stepBtn.classList.remove('active', 'completed');
      if (i < stepNum) {
        stepBtn.classList.add('completed');
      } else if (i === stepNum) {
        stepBtn.classList.add('active');
      }
    }
    const percent = Math.min(100, Math.max(0, ((stepNum - 1) / 6) * 100));
    if (stepProgressBar) stepProgressBar.style.width = `${percent}%`;
  }

  for (let i = 1; i <= 7; i++) {
    const btn = document.getElementById(`step-btn-${i}`);
    if (btn) {
      btn.addEventListener('click', () => {
        setStep(i);
        mapStepToTab(i);
      });
    }
  }

  function mapStepToTab(step) {
    switch(step) {
      case 1:
      case 2:
        switchTab('terminal');
        break;
      case 3:
        switchTab('detect');
        break;
      case 4:
        switchTab('cause');
        break;
      case 5:
        switchTab('fix');
        break;
      case 6:
        switchTab('terminal');
        break;
      case 7:
        switchTab('verify');
        break;
    }
  }

  // Populate presets for the currently chosen language
  function populatePresetsForLanguage(lang) {
    const matching = presets.filter(p => p.language === lang.toLowerCase());
    if (matching.length > 0) {
      presetSelect.innerHTML = matching.map(p => 
        `<option value="${p.id}">[${p.category}] ${p.name}</option>`
      ).join('');
      applyPreset(matching[0]);
    } else {
      presetSelect.innerHTML = `<option value="" disabled selected>No presets for ${lang}</option>`;
    }
  }

  // Fetch Presets and Languages from Server
  async function loadPresets() {
    try {
      const res = await fetch('/api/presets');
      const data = await res.json();
      if (data.ok && data.presets) {
        presets = data.presets;
        populatePresetsForLanguage(currentLanguage);
      }
    } catch (err) {
      showToast('Failed to load presets: ' + err.message, 'error');
    }
  }

  function applyPreset(preset) {
    currentPreset = preset;
    currentLanguage = preset.language || 'javascript';
    if (languageSelect && languageSelect.value !== currentLanguage) {
      languageSelect.value = currentLanguage;
    }
    buggyCode = preset.code;
    fixedCode = '';
    codeEditor.value = buggyCode;
    editorTitle.textContent = `[${currentLanguage.toUpperCase()}] ${preset.name}`;
    editorBadge.textContent = 'Original (Buggy)';
    editorBadge.className = 'badge';
    btnApplyFix.classList.add('hidden');
    updateEditorMetrics();
    resetPipelineViews();
    setStep(1);
    showToast(`Loaded ${preset.language.toUpperCase()} preset: ${preset.name}`);
  }

  // Language Selector Change Event
  if (languageSelect) {
    languageSelect.addEventListener('change', (e) => {
      currentLanguage = e.target.value;
      populatePresetsForLanguage(currentLanguage);
      showToast(`Switched language environment to: ${currentLanguage.toUpperCase()}`);
    });
  }

  // Preset Selector Change Event
  presetSelect.addEventListener('change', (e) => {
    const selected = presets.find(p => p.id === e.target.value);
    if (selected) applyPreset(selected);
  });

  btnResetCode.addEventListener('click', () => {
    if (currentPreset) {
      applyPreset(currentPreset);
    } else {
      codeEditor.value = '';
      updateEditorMetrics();
    }
  });

  // Toggle Diff View
  btnToggleDiff.addEventListener('click', () => {
    if (!fixedCode) {
      showToast('Generate a fix first to inspect the diff comparison.', 'info');
      return;
    }
    isDiffMode = !isDiffMode;
    btnToggleDiff.textContent = isDiffMode ? 'Show Editor' : 'Show Diff';
    editorViewMode.classList.toggle('hidden', isDiffMode);
    diffViewMode.classList.toggle('hidden', !isDiffMode);
    if (isDiffMode) {
      diffOriginalCode.textContent = buggyCode;
      diffFixedCode.textContent = fixedCode;
    }
  });

  // Apply Fix
  btnApplyFix.addEventListener('click', () => {
    if (!fixedCode) return;
    codeEditor.value = fixedCode;
    editorBadge.textContent = 'Fix Applied (Unverified)';
    editorBadge.className = 'badge info';
    btnApplyFix.classList.add('hidden');
    updateEditorMetrics();
    if (isDiffMode) {
      btnToggleDiff.click(); // switch back to editor
    }
    showToast('Applied surgical fix to editor. Ready for verification.', 'info');
  });

  function resetPipelineViews() {
    terminalOutput.innerHTML = `<div class="terminal-line placeholder">Click "Run Code" or "Run Full Flow" to execute the active ${currentLanguage.toUpperCase()} code in a secure sandbox.</div>`;
    terminalMeta.textContent = 'Status: Idle';
    terminalBadge.textContent = 'Ready';
    terminalBadge.className = 'tab-badge';

    findingsContainer.innerHTML = '<div class="empty-state">No scan completed yet. Run code or click "Detect Bugs" to start the Hunter audit.</div>';
    findingsSummary.textContent = `Scan your ${currentLanguage.toUpperCase()} code to identify vulnerabilities and defects.`;
    detectBadge.textContent = '0 Bugs';

    causeContainer.innerHTML = '<div class="empty-state">Select a detected finding to view the Hunter claim, Skeptic critique, and Referee final binding verdict.</div>';
    fixOverview.innerHTML = '<div class="empty-state">No fix generated yet. Advance the pipeline to generate a surgical remediation patch.</div>';
    verificationContainer.innerHTML = '<div class="empty-state">Fix has not been verified yet. Complete the fix generation to run the hybrid verifier suite.</div>';
    verifyBadge.textContent = 'Audit';
    verifyBadge.className = 'tab-badge success';
  }

  // Step 2: Run Code API
  async function runCode(codeToRun, isFixed = false) {
    setStep(isFixed ? 6 : 2);
    switchTab('terminal');
    terminalMeta.textContent = 'Executing...';
    terminalBadge.textContent = 'Running';
    terminalOutput.innerHTML = `<div class="terminal-line placeholder">⏳ Spawning isolated ${currentLanguage.toUpperCase()} process...</div>`;

    try {
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: codeToRun, language: currentLanguage })
      });
      const result = await res.json();
      
      let html = '';
      if (result.stdout) {
        html += result.stdout.split('\n').map(l => `<div class="terminal-line stdout">${escapeHtml(l)}</div>`).join('');
      }
      if (result.stderr) {
        html += result.stderr.split('\n').map(l => `<div class="terminal-line stderr">${escapeHtml(l)}</div>`).join('');
      }
      
      const statusClass = result.ok ? 'status-pass' : 'status-fail';
      const statusText = result.ok 
        ? `✔ Process exited cleanly with code 0 (${result.durationMs}ms)`
        : `✖ Process failed with exit code ${result.exitCode} (${result.durationMs}ms)`;
      
      html += `<div class="terminal-line ${statusClass}">${statusText}</div>`;
      terminalOutput.innerHTML = html;
      terminalMeta.textContent = `Exit: ${result.exitCode} | Duration: ${result.durationMs}ms | ${currentLanguage.toUpperCase()}`;
      terminalBadge.textContent = result.ok ? 'Pass' : 'Defect';
      terminalBadge.className = `tab-badge ${result.ok ? 'success' : 'warning'}`;

      return result;
    } catch (err) {
      terminalOutput.innerHTML = `<div class="terminal-line stderr">Network/Server Error: ${err.message}</div>`;
      terminalMeta.textContent = 'Status: Error';
      throw err;
    }
  }

  // Step 3: Detect Bugs API
  async function detectBugs() {
    setStep(3);
    switchTab('detect');
    findingsSummary.textContent = `Running adversarial Hunter heuristics on ${currentLanguage.toUpperCase()} source...`;
    findingsContainer.innerHTML = '<div class="empty-state">Auditing AST, tokens, and execution boundaries...</div>';

    try {
      const code = codeEditor.value;
      const res = await fetch('/api/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, language: currentLanguage })
      });
      const data = await res.json();
      detectedFindings = data.findings || [];
      detectBadge.textContent = `${detectedFindings.length} Bug${detectedFindings.length === 1 ? '' : 's'}`;

      if (detectedFindings.length === 0) {
        findingsSummary.textContent = `Audit complete: No defects found in active ${currentLanguage.toUpperCase()} code.`;
        findingsContainer.innerHTML = '<div class="empty-state">Zero defects identified. Code passes heuristics.</div>';
        return detectedFindings;
      }

      findingsSummary.textContent = `Identified ${detectedFindings.length} defect(s) in ${currentLanguage.toUpperCase()} requiring verification.`;
      findingsContainer.innerHTML = detectedFindings.map(f => `
        <div class="finding-card" data-bug-id="${f.bugId}">
          <div class="finding-card-header">
            <span class="finding-id">${f.bugId}</span>
            <div class="finding-tags">
              <span class="tag ${f.severity.toLowerCase()}">${f.severity}</span>
              <span class="tag">${f.category}</span>
              <span class="tag">${f.cwe}</span>
            </div>
          </div>
          <div class="finding-title">${escapeHtml(f.title)}</div>
          <div class="finding-desc">${escapeHtml(f.description)}</div>
          <div class="finding-snippet">Line ${f.line}: ${escapeHtml(f.codeSnippet)}</div>
        </div>
      `).join('');

      selectedFinding = detectedFindings[0];

      // Add click listeners to cards
      document.querySelectorAll('.finding-card').forEach(card => {
        card.addEventListener('click', () => {
          const bugId = card.dataset.bugId;
          selectedFinding = detectedFindings.find(f => f.bugId === bugId);
          findCause(selectedFinding);
        });
      });

      return detectedFindings;
    } catch (err) {
      findingsSummary.textContent = 'Detection failed: ' + err.message;
      throw err;
    }
  }

  // Step 4: Root Cause Analysis API
  async function findCause(finding) {
    setStep(4);
    switchTab('cause');
    causeContainer.innerHTML = '<div class="empty-state">Convening Hunter, Skeptic, and Referee debate...</div>';

    try {
      const code = codeEditor.value;
      const res = await fetch('/api/cause', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, findingId: finding ? finding.bugId : undefined, language: currentLanguage })
      });
      const data = await res.json();
      rootCauseData = data.cause;

      causeContainer.innerHTML = `
        <!-- Hunter Box -->
        <div class="debate-box debate-hunter">
          <div class="debate-header">
            <span>🎯 Hunter Assessment (${rootCauseData.findingId})</span>
          </div>
          <div class="debate-body">
            <div class="debate-field"><strong>Claim:</strong> ${escapeHtml(rootCauseData.hunter.claim)}</div>
            <div class="debate-field"><strong>Observed Evidence:</strong> ${escapeHtml(rootCauseData.hunter.evidence)}</div>
          </div>
        </div>

        <!-- Skeptic Box -->
        <div class="debate-box debate-skeptic">
          <div class="debate-header">
            <span>⚖️ Skeptic Cross-Examination</span>
          </div>
          <div class="debate-body">
            <div class="debate-field"><strong>Counter-Hypothesis:</strong> ${escapeHtml(rootCauseData.skeptic.critique)}</div>
            <div class="debate-field"><strong>Adversarial Test:</strong> ${escapeHtml(rootCauseData.skeptic.evaluation)}</div>
          </div>
        </div>

        <!-- Referee Box -->
        <div class="debate-box debate-referee">
          <div class="debate-header">
            <span>🛡️ Referee Final Binding Verdict [${escapeHtml(rootCauseData.referee.verdict)}]</span>
          </div>
          <div class="debate-body">
            <div class="debate-field"><strong>Root Cause:</strong> ${escapeHtml(rootCauseData.referee.rootCause)}</div>
            <div class="debate-field"><strong>Threat / Defect Vector:</strong> ${escapeHtml(rootCauseData.referee.threatVector)}</div>
            <div class="debate-field"><strong>Required Remediation:</strong> ${escapeHtml(rootCauseData.referee.remediation)}</div>
          </div>
        </div>
      `;

      return rootCauseData;
    } catch (err) {
      causeContainer.innerHTML = `<div class="empty-state">Error analyzing root cause: ${err.message}</div>`;
      throw err;
    }
  }

  // Step 5: Generate Fix API
  async function generateFix() {
    setStep(5);
    switchTab('fix');
    fixOverview.innerHTML = `<div class="empty-state">Synthesizing surgical remediation patch for ${currentLanguage.toUpperCase()}...</div>`;

    try {
      const code = codeEditor.value;
      const res = await fetch('/api/fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, findingId: selectedFinding ? selectedFinding.bugId : undefined, language: currentLanguage })
      });
      const data = await res.json();
      fixedCode = data.fixedCode;

      const isFixAvailable = !data.patchSummary || !data.patchSummary.toLowerCase().includes('unavailable');

      fixOverview.innerHTML = `
        <div class="fix-summary-title">${isFixAvailable ? 'Surgical Remediation Ready' : 'Remediation Analysis'} (${currentLanguage.toUpperCase()})</div>
        <div class="fix-explanation">${escapeHtml(data.explanation)}</div>
        <div class="fix-patch-preview">${escapeHtml(data.patchSummary)}</div>
        ${isFixAvailable ? `
        <div style="margin-top: 14px; display: flex; gap: 10px;">
          <button id="btn-quick-apply" class="btn btn-sm btn-success">Apply Fix Now</button>
          <button id="btn-quick-diff" class="btn btn-sm btn-action">View Side-by-Side Diff</button>
        </div>` : ''}
      `;

      if (isFixAvailable) {
        btnApplyFix.classList.remove('hidden');
        document.getElementById('btn-quick-apply').addEventListener('click', () => {
          btnApplyFix.click();
        });
        document.getElementById('btn-quick-diff').addEventListener('click', () => {
          btnToggleDiff.click();
        });
      } else {
        btnApplyFix.classList.add('hidden');
      }

      return fixedCode;
    } catch (err) {
      fixOverview.innerHTML = `<div class="empty-state">Error generating fix: ${err.message}</div>`;
      throw err;
    }
  }

  // Step 7: Verify Fix API
  async function verifyFix() {
    setStep(7);
    switchTab('verify');
    verificationContainer.innerHTML = `<div class="empty-state">Executing ${currentLanguage.toUpperCase()} hybrid verification checks (Syntax, Compilation, Invariants, Sandbox Execution)...</div>`;

    try {
      const codeToVerify = fixedCode || codeEditor.value;
      const res = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fixedCode: codeToVerify, language: currentLanguage })
      });
      const data = await res.json();

      const allOk = data.ok;
      if (allOk) {
        editorBadge.textContent = 'Fixed (Verified)';
        editorBadge.className = 'badge success';
      } else {
        editorBadge.textContent = 'Verification Failed';
        editorBadge.className = 'badge warning';
      }

      verificationContainer.innerHTML = `
        <div class="verification-status-banner">
          <div class="verification-icon">${allOk ? '🛡️' : '⚠️'}</div>
          <div>
            <div class="verification-headline">${allOk ? `HYBRID VERIFICATION PASSED (100% - ${currentLanguage.toUpperCase()})` : 'VERIFICATION FAILED'}</div>
            <div class="verification-subline">${allOk ? 'Zero residual vulnerabilities. Functional integrity and security invariants guaranteed.' : 'One or more required checks failed.'}</div>
          </div>
        </div>

        <div class="check-list">
          ${data.checks.map(c => `
            <div class="check-item">
              <div class="check-info">
                <span class="check-mark">${c.passed ? '✓' : '✗'}</span>
                <div>
                  <div class="check-name">${escapeHtml(c.name)}</div>
                  <div class="check-detail">${escapeHtml(c.detail)}</div>
                </div>
              </div>
              <span class="tag ${c.passed ? 'critical' : 'high'}" style="${c.passed ? 'background: rgba(16, 185, 129, 0.2); color: #34d399;' : ''}">${c.passed ? 'PASSED' : 'FAILED'}</span>
            </div>
          `).join('')}
        </div>
      `;

      verifyBadge.textContent = allOk ? 'Verified 4/4' : 'Failed';
      showToast(allOk ? 'Verification complete: All checks passed!' : 'Verification found issues.', allOk ? 'success' : 'error');

      return data;
    } catch (err) {
      verificationContainer.innerHTML = `<div class="empty-state">Verification error: ${err.message}</div>`;
      throw err;
    }
  }

  // Complete End-to-End Flow Pipeline
  async function runFullFlow() {
    btnRunFullFlow.disabled = true;
    btnRunFullFlow.innerHTML = '<span class="btn-icon">⏳</span> Hunting & Fixing...';

    try {
      showToast(`Starting complete 7-step pipeline for ${currentLanguage.toUpperCase()}...`, 'info');
      
      // 1. Enter Code
      setStep(1);
      await delay(400);

      // 2. Run Code
      showToast('Step 2: Executing buggy code...');
      await runCode(codeEditor.value, false);
      await delay(800);

      // 3. Detect Bug
      showToast('Step 3: Detecting vulnerabilities and defects...');
      const findings = await detectBugs();
      await delay(800);

      // 4. Find Cause
      showToast('Step 4: Analyzing root cause with Skeptic & Referee...');
      await findCause(findings[0]);
      await delay(800);

      // 5. Generate Fix
      showToast('Step 5: Generating surgical fix...');
      await generateFix();
      await delay(800);

      // Apply fix to editor automatically
      btnApplyFix.click();

      // 6. Run Fixed Code
      showToast('Step 6: Executing fixed code to confirm clean run...');
      await runCode(fixedCode, true);
      await delay(800);

      // 7. Verify Fix
      showToast('Step 7: Running hybrid verification suite...');
      const verifyResult = await verifyFix();

      if (verifyResult && verifyResult.ok) {
        showToast(`🎉 Complete ${currentLanguage.toUpperCase()} flow verified end-to-end!`, 'success');
      } else {
        showToast('Verification detected unresolved issues.', 'error');
      }
    } catch (err) {
      showToast('Flow interrupted: ' + err.message, 'error');
    } finally {
      btnRunFullFlow.disabled = false;
      btnRunFullFlow.innerHTML = '<span class="btn-icon">⚡</span> Run Full Flow';
    }
  }

  // Event Listeners for manual single-step advancement
  btnRunCode.addEventListener('click', () => runCode(codeEditor.value, false));
  btnActionStep2.addEventListener('click', () => runCode(codeEditor.value, false));
  btnActionStep3.addEventListener('click', detectBugs);
  btnReDetect.addEventListener('click', detectBugs);
  btnActionStep4.addEventListener('click', () => findCause(selectedFinding || detectedFindings[0]));
  btnActionStep5.addEventListener('click', generateFix);
  btnActionStep6.addEventListener('click', () => runCode(fixedCode || codeEditor.value, true));
  btnActionStep7.addEventListener('click', verifyFix);
  btnRunFullFlow.addEventListener('click', runFullFlow);

  function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Initialize
  loadPresets();
});
