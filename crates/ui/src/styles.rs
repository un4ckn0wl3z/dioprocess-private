//! CSS styles for the UI

/// Complete offline CSS styles
pub const CUSTOM_STYLES: &str = r#"
    /* Reset & Base */
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    html, body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        color: #eee;
        height: 100%;
        overflow: hidden;
    }

    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: transparent;
    }
    ::-webkit-scrollbar-thumb {
        background: rgba(0, 212, 255, 0.3);
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(0, 212, 255, 0.5);
    }

    /* Main Container */
    .main-container {
        height: 100vh;
        display: flex;
        flex-direction: column;
        outline: none;
    }

    /* Title Bar */
    .title-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        height: 36px;
        background: linear-gradient(to right, #020617, #0f172a);
        border-bottom: 1px solid rgba(34, 211, 238, 0.2);
        user-select: none;
        flex-shrink: 0;
    }
    .title-bar-drag {
        flex: 1;
        height: 100%;
        display: flex;
        align-items: center;
        padding-left: 12px;
        cursor: move;
    }
    .title-text {
        font-size: 14px;
        font-weight: 500;
        color: #22d3ee;
    }
    .title-bar-buttons {
        display: flex;
        height: 100%;
    }
    .title-btn {
        width: 48px;
        height: 100%;
        border: none;
        background: transparent;
        color: #9ca3af;
        font-size: 12px;
        cursor: pointer;
        transition: all 0.15s;
    }
    .title-btn:hover {
        background: rgba(255, 255, 255, 0.1);
        color: white;
    }
    .title-btn-close:hover {
        background: #dc2626;
        color: white;
    }

    /* Stats Bar */
    .stats-bar {
        background: linear-gradient(to right, rgba(15, 23, 42, 0.8), rgba(30, 41, 59, 0.8));
        border-bottom: 1px solid rgba(34, 211, 238, 0.1);
        padding: 8px 20px;
        display: flex;
        align-items: center;
        gap: 24px;
        font-size: 12px;
        flex-shrink: 0;
    }
    .stat-item {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .stat-item-right {
        margin-left: auto;
    }
    .stat-label {
        color: #6b7280;
    }
    .stat-bar {
        width: 96px;
        height: 8px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 4px;
        overflow: hidden;
    }
    .stat-bar-fill {
        height: 100%;
        transition: all 0.5s;
    }
    .stat-bar-cpu {
        background: linear-gradient(to right, #22d3ee, #0891b2);
    }
    .stat-bar-ram {
        background: linear-gradient(to right, #a855f7, #7c3aed);
    }
    .stat-value {
        font-family: monospace;
        min-width: 40px;
    }
    .stat-value-cyan { color: #22d3ee; }
    .stat-value-purple { color: #a855f7; min-width: 100px; }
    .stat-value-green { color: #4ade80; }
    .stat-value-yellow { color: #facc15; }

    /* Content Area */
    .content-area {
        max-width: 1152px;
        margin: 0 auto;
        padding: 20px;
        flex: 1;
        overflow: hidden;
        display: flex;
        flex-direction: column;
        width: 100%;
    }

    /* Header */
    .header-box {
        text-align: center;
        margin-bottom: 16px;
        padding: 16px;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        backdrop-filter: blur(4px);
        flex-shrink: 0;
    }
    .header-title {
        font-size: 24px;
        margin-bottom: 8px;
        color: #22d3ee;
        font-weight: bold;
    }
    .header-stats {
        display: flex;
        justify-content: center;
        gap: 32px;
        font-size: 14px;
        color: #9ca3af;
    }
    .header-shortcuts {
        color: #4b5563;
        font-size: 12px;
    }
    .status-message {
        margin-top: 12px;
        padding: 8px 16px;
        background: rgba(34, 211, 238, 0.2);
        border-radius: 6px;
        font-size: 14px;
        color: #22d3ee;
        display: inline-block;
    }

    /* Controls */
    .controls {
        display: flex;
        gap: 16px;
        margin-bottom: 16px;
        align-items: center;
        flex-wrap: wrap;
        flex-shrink: 0;
    }
    .search-input {
        flex: 1;
        min-width: 200px;
        padding: 12px 16px;
        border: none;
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.1);
        color: white;
        font-size: 14px;
        outline: none;
        transition: background 0.15s;
    }
    .search-input:focus {
        background: rgba(255, 255, 255, 0.15);
    }
    .search-input::placeholder {
        color: #6b7280;
    }
    .checkbox-label {
        display: flex;
        align-items: center;
        gap: 8px;
        color: #9ca3af;
        font-size: 14px;
        cursor: pointer;
        user-select: none;
    }
    .checkbox {
        width: 16px;
        height: 16px;
        cursor: pointer;
        accent-color: #22d3ee;
    }

    /* Buttons */
    .btn {
        padding: 12px 24px;
        border: none;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.15s;
    }
    .btn-primary {
        background: linear-gradient(to bottom right, #22d3ee, #0891b2);
        color: white;
    }
    .btn-primary:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(34, 211, 238, 0.4);
    }
    .btn-primary:active {
        transform: translateY(0);
    }
    .btn-danger {
        background: linear-gradient(to bottom right, #ef4444, #b91c1c);
        color: white;
    }
    .btn-danger:hover:not(:disabled) {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(239, 68, 68, 0.4);
    }
    .btn-danger:active:not(:disabled) {
        transform: translateY(0);
    }
    .btn-danger:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }

    /* Table */
    .table-container {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        flex: 1;
        overflow-y: auto;
        overflow-x: hidden;
        min-height: 0;
    }
    .process-table {
        width: 100%;
        border-collapse: collapse;
    }
    .table-header {
        position: sticky;
        top: 0;
        background: rgba(34, 211, 238, 0.2);
        backdrop-filter: blur(4px);
        z-index: 10;
    }
    .th {
        padding: 12px 16px;
        text-align: left;
        font-weight: 600;
        color: #22d3ee;
        border-bottom: 2px solid rgba(34, 211, 238, 0.3);
        font-size: 14px;
        user-select: none;
    }
    .th.sortable {
        cursor: pointer;
        transition: background 0.15s;
    }
    .th.sortable:hover {
        background: rgba(34, 211, 238, 0.3);
    }

    /* Process Row */
    .process-row {
        cursor: pointer;
        transition: background 0.15s;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .process-row:hover {
        background: rgba(34, 211, 238, 0.1);
    }
    .process-row.selected {
        border-left: 4px solid #ef4444;
        background: rgba(239, 68, 68, 0.2);
    }
    .process-row.selected:hover {
        background: rgba(239, 68, 68, 0.3);
    }
    .cell {
        padding: 12px 16px;
    }
    .cell-pid {
        font-family: monospace;
        color: #facc15;
        width: 80px;
    }
    .cell-name {
        font-weight: 500;
    }
    .cell-cpu {
        font-family: monospace;
        width: 80px;
        text-align: center;
    }
    .cell-threads {
        font-family: monospace;
        color: #a855f7;
        width: 80px;
        text-align: center;
    }
    .cell-memory {
        width: 176px;
    }
    .cell-path {
        font-size: 12px;
        color: #6b7280;
        max-width: 200px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .cell-path:hover {
        color: #9ca3af;
    }

    /* CPU Colors */
    .cpu-low { color: #4ade80; }
    .cpu-medium { color: #facc15; }
    .cpu-high { color: #f87171; }

    /* Memory Bar */
    .memory-bar-container {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .memory-bar-bg {
        flex: 1;
        height: 8px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 4px;
        overflow: hidden;
    }
    .memory-bar-fill {
        height: 100%;
        background: linear-gradient(to right, #4ade80, #22d3ee, #ef4444);
        border-radius: 4px;
        transition: width 0.3s;
    }
    .memory-text {
        font-family: monospace;
        color: #4ade80;
        font-size: 12px;
        min-width: 70px;
        text-align: right;
    }

    /* Context Menu */
    .context-menu {
        position: fixed;
        background: #1e293b;
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-radius: 8px;
        box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
        padding: 4px 0;
        min-width: 180px;
        z-index: 50;
    }
    .context-menu-item {
        width: 100%;
        padding: 8px 16px;
        text-align: left;
        font-size: 14px;
        color: #d1d5db;
        background: transparent;
        border: none;
        display: flex;
        align-items: center;
        gap: 8px;
        cursor: pointer;
        transition: background 0.15s;
    }
    .context-menu-item:hover:not(:disabled) {
        background: rgba(34, 211, 238, 0.2);
    }
    .context-menu-item:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    .context-menu-item-danger {
        color: #f87171;
    }
    .context-menu-item-danger:hover {
        background: rgba(239, 68, 68, 0.2);
    }
    .context-menu-item-warning {
        color: #fbbf24;
    }
    .context-menu-item-warning:hover {
        background: rgba(251, 191, 36, 0.2);
    }
    .context-menu-item-success {
        color: #4ade80;
    }
    .context-menu-item-success:hover {
        background: rgba(74, 222, 128, 0.2);
    }
    .context-menu-separator {
        height: 1px;
        background: rgba(34, 211, 238, 0.2);
        margin: 4px 0;
    }

    /* Context Menu Submenu */
    .context-menu-submenu {
        position: relative;
    }
    .context-menu-submenu-trigger {
        width: 100%;
        padding: 8px 16px;
        text-align: left;
        font-size: 14px;
        color: #d1d5db;
        background: transparent;
        border: none;
        display: flex;
        align-items: center;
        gap: 8px;
        cursor: pointer;
        transition: background 0.15s;
    }
    .context-menu-submenu-trigger:hover {
        background: rgba(34, 211, 238, 0.2);
    }
    .context-menu-submenu-trigger .arrow {
        margin-left: auto;
        font-size: 10px;
        color: #6b7280;
    }
    .context-menu-submenu-content {
        display: none;
        position: absolute;
        left: 100%;
        top: 0;
        background: #1e293b;
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-radius: 8px;
        box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
        padding: 4px 0;
        min-width: 160px;
        z-index: 51;
    }
    .context-menu-submenu:hover > .context-menu-submenu-content {
        display: block;
    }
    .context-menu-submenu-content .context-menu-submenu .context-menu-submenu-content {
        z-index: 52;
    }

    /* Module Import View */
    .module-import-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 20px;
        border-bottom: 1px solid rgba(34, 211, 238, 0.2);
        background: rgba(34, 211, 238, 0.05);
    }
    .module-import-header button {
        padding: 4px 12px;
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-radius: 4px;
        background: transparent;
        color: #22d3ee;
        cursor: pointer;
        font-size: 13px;
        transition: all 0.15s;
    }
    .module-import-header button:hover {
        background: rgba(34, 211, 238, 0.2);
    }
    .module-import-header span {
        font-size: 15px;
        font-weight: 600;
        color: #22d3ee;
    }
    .module-import-dll {
        padding: 8px 20px 4px;
        font-size: 14px;
        font-weight: 600;
        color: #fbbf24;
        border-bottom: 1px solid rgba(251, 191, 36, 0.15);
        margin-top: 8px;
    }
    .module-import-fn {
        padding: 3px 20px 3px 36px;
        font-family: 'Cascadia Code', 'Consolas', monospace;
        font-size: 12px;
        color: #9ca3af;
    }
    .module-import-fn:hover {
        color: #d1d5db;
        background: rgba(255, 255, 255, 0.03);
    }

    /* Thread Modal */
    .thread-modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 100;
    }
    .thread-modal {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-radius: 12px;
        width: 700px;
        max-width: 90vw;
        max-height: 80vh;
        display: flex;
        flex-direction: column;
        box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
    }
    .thread-modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 20px;
        border-bottom: 1px solid rgba(34, 211, 238, 0.2);
    }
    .thread-modal-title {
        font-size: 18px;
        font-weight: 600;
        color: #22d3ee;
    }
    .thread-modal-close {
        width: 32px;
        height: 32px;
        border: none;
        background: transparent;
        color: #9ca3af;
        font-size: 16px;
        cursor: pointer;
        border-radius: 6px;
        transition: all 0.15s;
    }
    .thread-modal-close:hover {
        background: #dc2626;
        color: white;
    }
    .thread-controls {
        display: flex;
        gap: 16px;
        padding: 12px 20px;
        align-items: center;
        border-bottom: 1px solid rgba(34, 211, 238, 0.1);
    }
    .thread-count {
        color: #9ca3af;
        font-size: 14px;
    }
    .thread-status-message {
        margin: 8px 20px;
        padding: 8px 16px;
        background: rgba(34, 211, 238, 0.2);
        border-radius: 6px;
        font-size: 14px;
        color: #22d3ee;
    }
    .thread-table-container {
        flex: 1;
        overflow-y: auto;
        padding: 0 20px 20px;
    }
    .thread-table {
        width: 100%;
        border-collapse: collapse;
    }
    .thread-row {
        cursor: pointer;
        transition: background 0.15s;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .thread-row:hover {
        background: rgba(34, 211, 238, 0.1);
    }
    .thread-row.selected {
        border-left: 4px solid #22d3ee;
        background: rgba(34, 211, 238, 0.2);
    }
    .cell-tid {
        font-family: monospace;
        color: #facc15;
    }
    .cell-actions {
        display: flex;
        gap: 8px;
    }
    .action-btn {
        width: 28px;
        height: 28px;
        border: none;
        border-radius: 4px;
        background: rgba(255, 255, 255, 0.1);
        cursor: pointer;
        font-size: 12px;
        transition: all 0.15s;
    }
    .action-btn:hover {
        transform: scale(1.1);
    }
    .action-btn-warning {
        color: #fbbf24;
    }
    .action-btn-warning:hover {
        background: rgba(251, 191, 36, 0.3);
    }
    .action-btn-success {
        color: #4ade80;
    }
    .action-btn-success:hover {
        background: rgba(74, 222, 128, 0.3);
    }
    .action-btn-danger {
        color: #f87171;
    }
    .action-btn-danger:hover {
        background: rgba(239, 68, 68, 0.3);
    }
    .btn-small {
        padding: 6px 12px;
        font-size: 12px;
    }

    /* Handle Window Styles */
    .handle-modal {
        width: 800px;
    }
    .handle-filter-input {
        padding: 6px 12px;
        border: none;
        border-radius: 6px;
        background: rgba(255, 255, 255, 0.1);
        color: white;
        font-size: 13px;
        width: 150px;
        outline: none;
    }
    .handle-filter-input:focus {
        background: rgba(255, 255, 255, 0.15);
    }
    .handle-filter-input::placeholder {
        color: #6b7280;
    }
    .cell-handle {
        font-family: monospace;
        color: #facc15;
    }
    .cell-access {
        font-family: monospace;
        color: #9ca3af;
        font-size: 12px;
    }
    .handle-type {
        font-size: 13px;
        padding: 2px 8px;
        border-radius: 4px;
        display: inline-block;
    }
    .handle-type-file {
        color: #4ade80;
        background: rgba(74, 222, 128, 0.15);
    }
    .handle-type-registry {
        color: #f472b6;
        background: rgba(244, 114, 182, 0.15);
    }
    .handle-type-process {
        color: #fb923c;
        background: rgba(251, 146, 60, 0.15);
    }
    .handle-type-sync {
        color: #a78bfa;
        background: rgba(167, 139, 250, 0.15);
    }
    .handle-type-memory {
        color: #22d3ee;
        background: rgba(34, 211, 238, 0.15);
    }
    .handle-type-security {
        color: #f87171;
        background: rgba(248, 113, 113, 0.15);
    }
    .handle-type-ipc {
        color: #fbbf24;
        background: rgba(251, 191, 36, 0.15);
    }
    .handle-type-namespace {
        color: #60a5fa;
        background: rgba(96, 165, 250, 0.15);
    }
    .handle-type-other {
        color: #9ca3af;
        background: rgba(156, 163, 175, 0.15);
    }

    /* Tab Bar */
    .tab-bar {
        display: flex;
        gap: 4px;
        padding: 0 20px;
        background: linear-gradient(to right, rgba(15, 23, 42, 0.6), rgba(30, 41, 59, 0.6));
        border-bottom: 1px solid rgba(34, 211, 238, 0.1);
        flex-shrink: 0;
    }
    .tab-item {
        padding: 12px 24px;
        color: #9ca3af;
        text-decoration: none;
        font-size: 14px;
        font-weight: 500;
        border-bottom: 2px solid transparent;
        transition: all 0.15s;
        cursor: pointer;
    }
    .tab-item:hover {
        color: #22d3ee;
        background: rgba(34, 211, 238, 0.1);
    }
    .tab-item.tab-active {
        color: #22d3ee;
        border-bottom-color: #22d3ee;
        background: rgba(34, 211, 238, 0.1);
    }

    /* Tab Content */
    .process-tab,
    .network-tab {
        flex: 1;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        outline: none;
    }

    /* Network Tab Specific Styles */
    .network-table .th {
        padding: 10px 12px;
        font-size: 13px;
    }
    .network-table .cell {
        padding: 10px 12px;
        font-size: 13px;
    }
    .cell-proto {
        font-family: monospace;
        font-weight: 600;
        width: 60px;
    }
    .proto-tcp {
        color: #22d3ee;
    }
    .proto-udp {
        color: #a855f7;
    }
    .cell-addr {
        font-family: monospace;
        color: #d1d5db;
    }
    .cell-port {
        font-family: monospace;
        color: #facc15;
        width: 70px;
        text-align: center;
    }
    .cell-state {
        font-size: 12px;
        font-weight: 500;
        width: 100px;
    }
    .state-listen {
        color: #4ade80;
    }
    .state-established {
        color: #22d3ee;
    }
    .state-waiting {
        color: #fbbf24;
    }
    .state-other {
        color: #9ca3af;
    }

    /* Filter Select */
    .filter-select {
        padding: 10px 12px;
        border: none;
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.1);
        color: white;
        font-size: 14px;
        outline: none;
        cursor: pointer;
        min-width: 130px;
    }
    .filter-select:focus {
        background: rgba(255, 255, 255, 0.15);
    }
    .filter-select option {
        background: #1e293b;
        color: white;
    }
"#;
