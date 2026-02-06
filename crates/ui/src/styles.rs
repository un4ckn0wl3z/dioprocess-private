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
        app-region: drag;
        -webkit-app-region: drag;
    }
    .title-text {
        font-size: 14px;
        font-weight: 500;
        color: #22d3ee;
    }
    .title-bar-buttons {
        display: flex;
        height: 100%;
        app-region: no-drag;
        -webkit-app-region: no-drag;
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
    .btn-secondary {
        background: linear-gradient(to bottom right, #334155, #1e293b);
        color: #e2e8f0;
        border: 1px solid rgba(148, 163, 184, 0.3);
    }
    .btn-secondary:hover {
        background: linear-gradient(to bottom right, #475569, #334155);
        border-color: rgba(148, 163, 184, 0.5);
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
    }
    .btn-secondary:active {
        transform: translateY(0);
    }
    .btn-secondary.active {
        background: linear-gradient(to bottom right, #164e63, #0e7490);
        border-color: rgba(34, 211, 238, 0.5);
        color: #22d3ee;
    }

    /* Tree View */
    .tree-name-container {
        display: flex;
        align-items: center;
        white-space: nowrap;
        overflow: hidden;
    }
    .tree-guide {
        display: inline-block;
        width: 20px;
        text-align: center;
        color: rgba(148, 163, 184, 0.4);
        font-family: monospace;
        flex-shrink: 0;
        user-select: none;
    }
    .tree-connector {
        display: inline-block;
        width: 20px;
        text-align: center;
        color: rgba(148, 163, 184, 0.4);
        font-family: monospace;
        flex-shrink: 0;
        user-select: none;
    }
    .tree-toggle {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 18px;
        height: 18px;
        color: #22d3ee;
        cursor: pointer;
        flex-shrink: 0;
        user-select: none;
        border-radius: 3px;
        font-size: 10px;
        transition: background 0.15s;
    }
    .tree-toggle:hover {
        background: rgba(34, 211, 238, 0.15);
    }
    .tree-toggle-placeholder {
        display: inline-block;
        width: 18px;
        flex-shrink: 0;
    }
    .tree-process-name {
        overflow: hidden;
        text-overflow: ellipsis;
        padding-left: 4px;
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
    .cell-arch {
        font-family: monospace;
        font-size: 12px;
        width: 50px;
        text-align: center;
        color: #60a5fa;
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
        bottom: 0;
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

    /* Multi-column menu layout for DLL Unhook list */
    .context-menu-submenu:hover > .context-menu-columns {
        display: flex;
        flex-direction: row;
        gap: 0;
        max-height: 80vh;
        overflow-y: auto;
    }
    .context-menu-column {
        display: flex;
        flex-direction: column;
        min-width: 180px;
        border-right: 1px solid rgba(34, 211, 238, 0.15);
    }
    .context-menu-column:last-child {
        border-right: none;
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

    /* Experimental Badge */
    .experimental-badge {
        font-size: 9px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        padding: 2px 6px;
        margin-left: 6px;
        border-radius: 4px;
        background: rgba(251, 191, 36, 0.2);
        color: #fbbf24;
        border: 1px solid rgba(251, 191, 36, 0.3);
        vertical-align: middle;
    }

    /* Tab Content */
    .process-tab,
    .network-tab,
    .service-tab {
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


    /* About Modal */
    .about-modal-overlay {
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

    .about-modal {
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

    .about-modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 20px;
        border-bottom: 1px solid rgba(34, 211, 238, 0.2);
    }

    .about-modal-title {
        font-size: 18px;
        font-weight: 600;
        color: #22d3ee;
    }

    .about-modal-close {
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

    .about-modal-close:hover {
        background: #dc2626;
        color: white;
    }

    .about-controls {
        display: flex;
        gap: 16px;
        padding: 12px 20px;
        align-items: center;
        border-bottom: 1px solid rgba(34, 211, 238, 0.1);
    }    

    .about-detail {
        color: #9ca3af;
        font-size: 14px;
    }

    .about-link,
    .about-link:link,
    .about-link:visited {
        color: #86efac;
        text-decoration: none;
    }

    .about-link:hover,
    .about-link:active {
        color: #4ade80;
        text-decoration: underline;
    }

    /* Service Tab Styles */
    .service-table .th {
        padding: 10px 12px;
        font-size: 13px;
    }
    .service-table .cell {
        padding: 10px 12px;
        font-size: 13px;
    }
    .cell-svc-name {
        font-weight: 500;
        max-width: 180px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .cell-svc-display {
        max-width: 200px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .cell-svc-desc {
        font-size: 12px;
        color: #9ca3af;
        max-width: 250px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .cell-svc-desc:hover {
        color: #d1d5db;
    }
    .cell-svc-path {
        font-size: 12px;
        color: #6b7280;
        max-width: 200px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .cell-svc-path:hover {
        color: #9ca3af;
    }
    .cell-svc-status {
        font-size: 12px;
        font-weight: 600;
        width: 110px;
    }
    .cell-svc-start-type {
        font-size: 12px;
        font-weight: 500;
        width: 100px;
    }
    .cell-svc-pid {
        font-family: monospace;
        color: #facc15;
        width: 70px;
        text-align: center;
    }
    .svc-running { color: #4ade80; }
    .svc-stopped { color: #f87171; }
    .svc-paused { color: #fbbf24; }
    .svc-pending { color: #fb923c; }
    .svc-unknown { color: #9ca3af; }
    .svc-start-auto { color: #4ade80; }
    .svc-start-manual { color: #60a5fa; }
    .svc-start-disabled { color: #f87171; }
    .svc-start-other { color: #9ca3af; }

    /* Create Service Modal */
    .create-svc-modal-overlay {
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
    .create-svc-modal {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-radius: 12px;
        width: 550px;
        max-width: 90vw;
        display: flex;
        flex-direction: column;
        box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
    }
    .create-svc-modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 20px;
        border-bottom: 1px solid rgba(34, 211, 238, 0.2);
    }
    .create-svc-modal-title {
        font-size: 18px;
        font-weight: 600;
        color: #22d3ee;
    }
    .create-svc-modal-close {
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
    .create-svc-modal-close:hover {
        background: #dc2626;
        color: white;
    }
    .create-svc-form {
        padding: 20px;
        display: flex;
        flex-direction: column;
        gap: 16px;
    }
    .create-svc-field {
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    .create-svc-label {
        font-size: 13px;
        font-weight: 500;
        color: #9ca3af;
    }
    .create-svc-input {
        padding: 10px 14px;
        border: 1px solid rgba(34, 211, 238, 0.2);
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.08);
        color: white;
        font-size: 14px;
        outline: none;
        transition: border-color 0.15s;
    }
    .create-svc-input:focus {
        border-color: rgba(34, 211, 238, 0.5);
        background: rgba(255, 255, 255, 0.12);
    }
    .create-svc-input::placeholder {
        color: #4b5563;
    }
    .create-svc-path-row {
        display: flex;
        gap: 8px;
    }
    .create-svc-path-row .create-svc-input {
        flex: 1;
    }
    .create-svc-btn-browse {
        padding: 10px 16px;
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-radius: 8px;
        background: rgba(34, 211, 238, 0.1);
        color: #22d3ee;
        font-size: 14px;
        cursor: pointer;
        transition: all 0.15s;
        white-space: nowrap;
    }
    .create-svc-btn-browse:hover {
        background: rgba(34, 211, 238, 0.2);
    }
    .create-svc-actions {
        display: flex;
        justify-content: flex-end;
        gap: 12px;
        padding: 16px 20px;
        border-top: 1px solid rgba(34, 211, 238, 0.1);
    }
    .btn-cancel {
        padding: 10px 20px;
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 8px;
        background: transparent;
        color: #9ca3af;
        font-size: 14px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.15s;
    }
    .btn-cancel:hover {
        background: rgba(255, 255, 255, 0.1);
        color: white;
    }

    /* Memory Window */
    .memory-modal {
        width: 950px;
    }
    .mem-state-commit { color: #4ade80; }
    .mem-state-reserve { color: #facc15; }
    .mem-state-free { color: #6b7280; }
    .mem-type-image { color: #22d3ee; }
    .mem-type-mapped { color: #a855f7; }
    .mem-type-private { color: #fb923c; }

    /* Hex dump */
    .hex-dump-container {
        font-family: 'Cascadia Code', 'Consolas', monospace;
        font-size: 13px;
        overflow-y: auto;
        flex: 1;
        padding: 0 20px 20px;
    }
    .hex-dump-header {
        display: flex;
        gap: 16px;
        padding: 8px 0;
        color: #6b7280;
        font-weight: 600;
        border-bottom: 1px solid rgba(34, 211, 238, 0.2);
        position: sticky;
        top: 0;
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        z-index: 1;
    }
    .hex-dump-line {
        display: flex;
        gap: 16px;
        padding: 2px 0;
        transition: background 0.1s;
    }
    .hex-dump-line:hover {
        background: rgba(34, 211, 238, 0.08);
    }
    .hex-offset {
        color: #facc15;
        min-width: 100px;
    }
    .hex-bytes {
        color: #9ca3af;
        min-width: 420px;
        letter-spacing: 0.5px;
    }
    .hex-ascii {
        color: #4ade80;
        min-width: 160px;
    }
    .hex-pagination {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 20px;
        border-bottom: 1px solid rgba(34, 211, 238, 0.1);
    }
    .hex-pagination button {
        padding: 4px 12px;
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-radius: 4px;
        background: transparent;
        color: #22d3ee;
        cursor: pointer;
        font-size: 13px;
        transition: all 0.15s;
    }
    .hex-pagination button:hover:not(:disabled) {
        background: rgba(34, 211, 238, 0.2);
    }
    .hex-pagination button:disabled {
        opacity: 0.4;
        cursor: not-allowed;
    }
    .hex-pagination span {
        color: #9ca3af;
        font-size: 13px;
    }

    /* Graph Window */
    .graph-modal {
        width: 500px;
    }
    .graph-content {
        padding: 16px 20px;
        display: flex;
        flex-direction: column;
        gap: 20px;
    }
    .graph-controls {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .graph-interval {
        color: #6b7280;
        font-size: 12px;
        margin-left: auto;
    }
    .graph-section {
        display: flex;
        flex-direction: column;
        gap: 8px;
    }
    .graph-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .graph-label {
        color: #9ca3af;
        font-size: 13px;
        font-weight: 500;
    }
    .graph-value {
        font-size: 18px;
        font-weight: 600;
        font-family: 'Cascadia Code', 'Consolas', monospace;
    }
    .graph-value-cpu {
        color: #22d3ee;
    }
    .graph-value-mem {
        color: #a855f7;
    }
    .graph-container {
        position: relative;
        background: rgba(0, 0, 0, 0.3);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        padding: 8px;
    }
    .graph-container svg {
        display: block;
    }
    .graph-grid {
        stroke: rgba(255, 255, 255, 0.1);
        stroke-width: 1;
    }
    .graph-line {
        fill: none;
        stroke-width: 2;
    }
    .graph-line-cpu {
        stroke: #22d3ee;
    }
    .graph-line-mem {
        stroke: #a855f7;
    }
    .graph-fill {
        opacity: 0.2;
    }
    .graph-fill-cpu {
        fill: #22d3ee;
    }
    .graph-fill-mem {
        fill: #a855f7;
    }
    .graph-y-labels {
        position: absolute;
        right: 12px;
        top: 8px;
        bottom: 8px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        font-size: 10px;
        color: #6b7280;
        pointer-events: none;
    }

    /* Create Process Modal */
    .create-process-modal-overlay {
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
    .create-process-modal {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-radius: 12px;
        width: 550px;
        max-width: 90vw;
        display: flex;
        flex-direction: column;
        box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
    }
    .create-process-modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 20px;
        border-bottom: 1px solid rgba(34, 211, 238, 0.2);
    }
    .create-process-modal-title {
        font-size: 18px;
        font-weight: 600;
        color: #22d3ee;
    }
    .create-process-modal-close {
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
    .create-process-modal-close:hover {
        background: #dc2626;
        color: white;
    }
    .create-process-form {
        padding: 20px;
        display: flex;
        flex-direction: column;
        gap: 16px;
    }
    .create-process-field {
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    .create-process-label {
        font-size: 13px;
        font-weight: 500;
        color: #9ca3af;
    }
    .create-process-input {
        padding: 10px 14px;
        border: 1px solid rgba(34, 211, 238, 0.2);
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.08);
        color: white;
        font-size: 14px;
        outline: none;
        transition: border-color 0.15s;
    }
    .create-process-input:focus {
        border-color: rgba(34, 211, 238, 0.5);
        background: rgba(255, 255, 255, 0.12);
    }
    .create-process-input::placeholder {
        color: #4b5563;
    }
    .create-process-path-row {
        display: flex;
        gap: 8px;
    }
    .create-process-path-row .create-process-input {
        flex: 1;
    }
    .create-process-btn-browse {
        padding: 10px 16px;
        border: 1px solid rgba(34, 211, 238, 0.3);
        border-radius: 8px;
        background: rgba(34, 211, 238, 0.1);
        color: #22d3ee;
        font-size: 14px;
        cursor: pointer;
        transition: all 0.15s;
        white-space: nowrap;
    }
    .create-process-btn-browse:hover {
        background: rgba(34, 211, 238, 0.2);
    }
    .create-process-radio-group {
        display: flex;
        gap: 24px;
    }
    .create-process-radio-label {
        display: flex;
        align-items: center;
        gap: 8px;
        color: #d1d5db;
        font-size: 14px;
        cursor: pointer;
    }
    .create-process-radio-label input[type="radio"] {
        accent-color: #22d3ee;
        width: 16px;
        height: 16px;
        cursor: pointer;
    }
    .create-process-checkbox-label {
        display: flex;
        align-items: center;
        gap: 8px;
        color: #d1d5db;
        font-size: 14px;
        cursor: pointer;
    }
    .create-process-status {
        padding: 10px 14px;
        border-radius: 8px;
        font-size: 14px;
    }
    .create-process-status-success {
        background: rgba(74, 222, 128, 0.15);
        color: #4ade80;
        border: 1px solid rgba(74, 222, 128, 0.3);
    }
    .create-process-status-error {
        background: rgba(248, 113, 113, 0.15);
        color: #f87171;
        border: 1px solid rgba(248, 113, 113, 0.3);
    }
    .create-process-actions {
        display: flex;
        justify-content: flex-end;
        gap: 12px;
        padding: 16px 20px;
        border-top: 1px solid rgba(34, 211, 238, 0.1);
    }

    /* IAT Hook Scan Status */
    .status-hooked {
        color: #f87171;
        font-weight: 600;
    }
    .status-clean {
        color: #4ade80;
        font-weight: 500;
    }
    .mono {
        font-family: 'Cascadia Code', 'Consolas', monospace;
        color: #facc15;
        font-size: 13px;
    }

    /* String Scan Window */
    .string-scan-modal {
        width: 1000px;
    }
    .cell-string-value {
        font-family: 'Cascadia Code', 'Consolas', monospace;
        font-size: 12px;
        max-width: 400px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .encoding-badge {
        font-size: 11px;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 500;
    }
    .encoding-ascii {
        color: #4ade80;
        background: rgba(74, 222, 128, 0.15);
    }
    .encoding-utf16 {
        color: #a78bfa;
        background: rgba(167, 139, 250, 0.15);
    }
    .min-length-input {
        width: 60px;
        padding: 6px 10px;
        border: 1px solid rgba(34, 211, 238, 0.2);
        border-radius: 6px;
        background: rgba(255, 255, 255, 0.08);
        color: white;
        font-size: 13px;
        outline: none;
        text-align: center;
    }
    .min-length-input:focus {
        border-color: rgba(34, 211, 238, 0.5);
        background: rgba(255, 255, 255, 0.12);
    }
    .context-menu-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        z-index: 49;
    }

    /* Callback Tab Styles */
    .callback-tab {
        flex: 1;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        outline: none;
    }

    .callback-table .th {
        padding: 10px 12px;
        font-size: 13px;
    }
    .callback-table .cell {
        padding: 10px 12px;
        font-size: 13px;
    }
    .cell-time {
        font-family: 'Cascadia Code', 'Consolas', monospace;
        color: #9ca3af;
        width: 110px;
    }
    .cell-event-type {
        font-weight: 600;
        width: 140px;
    }
    .event-type-process-create {
        color: #4ade80;
    }
    .event-type-process-exit {
        color: #f87171;
    }
    .event-type-thread-create {
        color: #60a5fa;
    }
    .event-type-thread-exit {
        color: #fbbf24;
    }
    .event-type-image-load {
        color: #a78bfa;
    }
    .event-type-handle-process {
        color: #f472b6;
    }
    .event-type-handle-thread {
        color: #fb7185;
    }
    .event-type-registry-read {
        color: #38bdf8;
    }
    .event-type-registry-write {
        color: #fb923c;
    }
    .callback-filter-select {
        min-width: 180px;
    }
    .pagination-controls {
        display: flex;
        align-items: center;
        gap: 4px;
        margin-left: auto;
    }
    .pagination-controls .btn-small {
        padding: 4px 8px;
        font-size: 12px;
        min-width: 28px;
    }
    .page-info {
        font-size: 12px;
        color: #9ca3af;
        padding: 0 8px;
    }
    .cell-details {
        font-size: 12px;
        color: #9ca3af;
        max-width: 350px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .cell-details:hover {
        color: #d1d5db;
    }

    /* Driver status indicator */
    .driver-status {
        font-size: 12px;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 12px;
        margin-left: 16px;
    }
    .driver-status-loaded {
        background: rgba(74, 222, 128, 0.2);
        color: #4ade80;
        border: 1px solid rgba(74, 222, 128, 0.3);
    }
    .driver-status-not-loaded {
        background: rgba(248, 113, 113, 0.2);
        color: #f87171;
        border: 1px solid rgba(248, 113, 113, 0.3);
    }

    /* Driver not loaded notice */
    .driver-not-loaded-notice {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 60px 40px;
        text-align: center;
    }
    .driver-not-loaded-notice h2 {
        font-size: 20px;
        color: #f87171;
        margin-bottom: 16px;
    }
    .driver-not-loaded-notice p {
        color: #9ca3af;
        margin-bottom: 16px;
        font-size: 14px;
    }
    .driver-instructions {
        background: rgba(0, 0, 0, 0.4);
        padding: 16px 24px;
        border-radius: 8px;
        font-family: 'Cascadia Code', 'Consolas', monospace;
        font-size: 13px;
        color: #22d3ee;
        text-align: left;
        white-space: pre-wrap;
        margin-bottom: 16px;
        border: 1px solid rgba(34, 211, 238, 0.2);
    }
    .driver-note {
        color: #6b7280;
        font-size: 12px;
        font-style: italic;
    }

    /* Collection status indicator */
    .collection-status {
        font-size: 12px;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 12px;
        margin-left: 8px;
    }
    .collection-active {
        background: rgba(74, 222, 128, 0.2);
        color: #4ade80;
        border: 1px solid rgba(74, 222, 128, 0.3);
    }
    .collection-inactive {
        background: rgba(251, 191, 36, 0.2);
        color: #fbbf24;
        border: 1px solid rgba(251, 191, 36, 0.3);
    }

    /* Success button */
    .btn-success {
        background: linear-gradient(to bottom right, #4ade80, #22c55e);
        color: white;
    }
    .btn-success:hover:not(:disabled) {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(74, 222, 128, 0.4);
    }
    .btn-success:active:not(:disabled) {
        transform: translateY(0);
    }
    .btn-success:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }

"#;
