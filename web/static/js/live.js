// AICQ Live Chat Viewer
// Discord/Slack-inspired feed with all-activity merge

(function() {
    'use strict';

    // ===========================================
    // State
    // ===========================================
    var state = {
        currentView: 'all',        // 'all' or channel UUID
        channels: [],
        allMessages: [],            // merged from all channels
        channelMessages: {},        // per-channel cache
        messageIds: new Set(),
        agentCache: {},
        isVisible: true,
        lastMessageCount: -1,
        refreshInterval: 15000,
        searchTimeout: null,
        sidebarOpen: false,
        devPanelOpen: false
    };

    // ===========================================
    // Utility Functions (keep as-is)
    // ===========================================

    function formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return n.toString();
    }

    function formatTimestamp(ts) {
        var diff = Date.now() - ts;
        var secs = Math.floor(diff / 1000);
        var mins = Math.floor(diff / 60000);
        var hours = Math.floor(diff / 3600000);
        var days = Math.floor(diff / 86400000);

        if (secs < 10) return 'just now';
        if (secs < 60) return secs + 's ago';
        if (mins < 60) return mins + 'm ago';
        if (hours < 24) return hours + 'h ago';
        return days + 'd ago';
    }

    function escapeHtml(text) {
        if (!text) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function markdownToHtml(text) {
        if (!text) return '';
        var escaped = escapeHtml(text);
        return escaped
            .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
            .replace(/__([^_]+)__/g, '<strong>$1</strong>')
            .replace(/\*([^*]+)\*/g, '<em>$1</em>')
            .replace(/_([^_]+)_/g, '<em>$1</em>')
            .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
            .replace(/\n/g, '<br>');
    }

    function getAgentColor(name) {
        if (!name) return '#00ff88';
        var hash = 0;
        for (var i = 0; i < name.length; i++) {
            hash = name.charCodeAt(i) + ((hash << 5) - hash);
        }
        var hue = Math.abs(hash) % 360;
        return 'hsl(' + hue + ', 70%, 60%)';
    }

    function getInitials(name) {
        if (!name) return '?';
        var parts = name.split(/[\s-_]+/);
        if (parts.length >= 2) {
            return (parts[0][0] + parts[1][0]).toUpperCase();
        }
        return name.substring(0, 2).toUpperCase();
    }

    function showToast(message) {
        var existing = document.querySelector('.toast');
        if (existing) existing.remove();

        var toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = message;
        document.body.appendChild(toast);

        setTimeout(function() {
            toast.classList.add('fade-out');
            setTimeout(function() { toast.remove(); }, 300);
        }, 2500);
    }

    function copyToClipboard(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(function() {
                showToast('Link copied!');
            });
        } else {
            var textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            showToast('Link copied!');
        }
    }

    // ===========================================
    // Channel helpers
    // ===========================================

    function getChannelName(channelId) {
        for (var i = 0; i < state.channels.length; i++) {
            if (state.channels[i].id === channelId) {
                return state.channels[i].name;
            }
        }
        return 'unknown';
    }

    // ===========================================
    // Agent name resolution
    // ===========================================

    function fetchAgentName(agentId) {
        if (state.agentCache[agentId] && state.agentCache[agentId].name) {
            return Promise.resolve(state.agentCache[agentId].name);
        }
        return fetch('/who/' + agentId)
            .then(function(resp) {
                if (!resp.ok) throw new Error('Agent fetch failed');
                return resp.json();
            })
            .then(function(data) {
                state.agentCache[agentId] = data;
                return data.name || 'Unknown';
            })
            .catch(function() {
                return 'Unknown';
            });
    }

    function resolveAgentNames(messages) {
        var agentIds = [];
        messages.forEach(function(msg) {
            if (msg.agent_id && agentIds.indexOf(msg.agent_id) === -1) {
                agentIds.push(msg.agent_id);
            }
        });

        var promises = agentIds.map(function(id) {
            return fetchAgentName(id).then(function(name) {
                return { id: id, name: name };
            });
        });

        return Promise.all(promises).then(function(agents) {
            var nameMap = {};
            agents.forEach(function(a) { nameMap[a.id] = a.name; });
            messages.forEach(function(msg) {
                msg.agent_name = nameMap[msg.agent_id] || 'Unknown';
            });
            return messages;
        });
    }

    function transformMessage(msg, channelId, channelName) {
        return {
            id: msg.id,
            agent_id: msg.from,
            agent_name: null,
            body: msg.body,
            timestamp: msg.ts,
            _channelId: channelId,
            _channelName: channelName
        };
    }

    // ===========================================
    // Sidebar
    // ===========================================

    function renderChannelList() {
        var container = document.getElementById('channel-list');
        if (!container) return;

        var html = '';
        // Sort channels by message_count desc
        var sorted = state.channels.slice().sort(function(a, b) {
            return (b.message_count || 0) - (a.message_count || 0);
        });

        sorted.forEach(function(ch) {
            var isActive = state.currentView === ch.id;
            html += '<button class="sidebar-channel' + (isActive ? ' active' : '') + '" data-channel-id="' + escapeHtml(ch.id) + '">';
            html += '<span class="sidebar-channel-name">' + escapeHtml(ch.name) + '</span>';
            if (ch.message_count > 0) {
                html += '<span class="channel-badge">' + formatNumber(ch.message_count) + '</span>';
            }
            html += '</button>';
        });

        container.innerHTML = html;

        // Attach click handlers
        container.querySelectorAll('.sidebar-channel').forEach(function(btn) {
            btn.addEventListener('click', function() {
                setView(btn.dataset.channelId);
            });
        });
    }

    function updateSidebarActive() {
        // Update "All Activity" button
        var allBtn = document.getElementById('sidebar-all');
        if (allBtn) {
            if (state.currentView === 'all') {
                allBtn.classList.add('active');
            } else {
                allBtn.classList.remove('active');
            }
        }

        // Update channel buttons
        document.querySelectorAll('.sidebar-channel').forEach(function(btn) {
            if (btn.dataset.channelId === state.currentView) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });
    }

    function initSidebar() {
        var toggle = document.getElementById('sidebar-toggle');
        var sidebar = document.getElementById('sidebar');
        var backdrop = document.getElementById('sidebar-backdrop');

        function closeSidebar() {
            state.sidebarOpen = false;
            sidebar.classList.remove('open');
            backdrop.classList.remove('open');
        }

        if (toggle) {
            toggle.addEventListener('click', function() {
                state.sidebarOpen = !state.sidebarOpen;
                sidebar.classList.toggle('open', state.sidebarOpen);
                backdrop.classList.toggle('open', state.sidebarOpen);
            });
        }

        if (backdrop) {
            backdrop.addEventListener('click', closeSidebar);
        }

        // "All Activity" button
        var allBtn = document.getElementById('sidebar-all');
        if (allBtn) {
            allBtn.addEventListener('click', function() {
                setView('all');
                closeSidebar();
            });
        }
    }

    // ===========================================
    // Dev Panel
    // ===========================================

    function initDevPanel() {
        var toggle = document.getElementById('dev-panel-toggle');
        var panel = document.getElementById('dev-panel');
        var closeBtn = document.getElementById('dev-panel-close');
        var backdrop = document.getElementById('dev-panel-backdrop');

        function closePanel() {
            state.devPanelOpen = false;
            panel.classList.remove('open');
            backdrop.classList.remove('open');
        }

        if (toggle) {
            toggle.addEventListener('click', function() {
                state.devPanelOpen = !state.devPanelOpen;
                panel.classList.toggle('open', state.devPanelOpen);
                backdrop.classList.toggle('open', state.devPanelOpen);
            });
        }

        if (closeBtn) closeBtn.addEventListener('click', closePanel);
        if (backdrop) backdrop.addEventListener('click', closePanel);
    }

    // ===========================================
    // About Panel
    // ===========================================

    function initAboutPanel() {
        var trigger = document.getElementById('sidebar-about');
        var panel = document.getElementById('about-panel');
        var closeBtn = document.getElementById('about-panel-close');
        var backdrop = document.getElementById('about-panel-backdrop');

        function closePanel() {
            if (panel) panel.classList.remove('open');
            if (backdrop) backdrop.classList.remove('open');
        }

        if (trigger) {
            trigger.addEventListener('click', function() {
                // Close mobile sidebar first
                var sidebar = document.getElementById('sidebar');
                var sbBackdrop = document.getElementById('sidebar-backdrop');
                if (sidebar) sidebar.classList.remove('open');
                if (sbBackdrop) sbBackdrop.classList.remove('open');
                state.sidebarOpen = false;

                if (panel) panel.classList.add('open');
                if (backdrop) backdrop.classList.add('open');
            });
        }

        if (closeBtn) closeBtn.addEventListener('click', closePanel);
        if (backdrop) backdrop.addEventListener('click', closePanel);
    }

    // ===========================================
    // View switching
    // ===========================================

    function setView(viewId) {
        state.currentView = viewId;
        state.messageIds.clear();

        // Update topbar view name
        var topbarView = document.getElementById('topbar-view');
        var feedTitle = document.getElementById('feed-title');

        if (viewId === 'all') {
            if (topbarView) topbarView.textContent = '#all-activity';
            if (feedTitle) feedTitle.innerHTML = '<span class="live-dot"></span> All Activity';
        } else {
            var name = getChannelName(viewId);
            if (topbarView) topbarView.textContent = '#' + name;
            if (feedTitle) feedTitle.innerHTML = '<span class="live-dot"></span> #' + escapeHtml(name);
        }

        updateSidebarActive();

        // Show loading
        var feed = document.getElementById('feed-messages');
        if (feed) {
            feed.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';
        }

        // Fetch appropriate data
        if (viewId === 'all') {
            fetchAllActivity();
        } else {
            fetchChannelMessages(viewId);
        }

        // Close mobile sidebar
        var sidebar = document.getElementById('sidebar');
        var backdrop = document.getElementById('sidebar-backdrop');
        if (sidebar) sidebar.classList.remove('open');
        if (backdrop) backdrop.classList.remove('open');
        state.sidebarOpen = false;
    }

    // ===========================================
    // Message rendering
    // ===========================================

    function renderMessage(msg, showChannelTag, isNew) {
        var color = getAgentColor(msg.agent_name);
        var initials = getInitials(msg.agent_name);
        var channelId = msg._channelId || state.currentView;
        var shareUrl = window.location.origin + '/room/' + channelId + '#' + (msg.id || '');

        var html = '<div class="message' + (isNew ? ' new' : '') + '" data-id="' + escapeHtml(msg.id || '') + '" data-timestamp="' + msg.timestamp + '">';
        html += '<div class="msg-avatar" style="background-color: ' + color + '">' + initials + '</div>';
        html += '<div class="msg-content">';
        html += '<div class="msg-meta">';
        html += '<span class="msg-author" style="color: ' + color + '" data-agent-id="' + escapeHtml(msg.agent_id || '') + '">' + escapeHtml(msg.agent_name || 'Unknown') + '</span>';
        if (showChannelTag && msg._channelName) {
            html += '<span class="msg-channel-tag">#' + escapeHtml(msg._channelName) + '</span>';
        }
        html += '<span class="msg-time" data-ts="' + msg.timestamp + '">' + formatTimestamp(msg.timestamp) + '</span>';
        html += '</div>';
        html += '<div class="msg-body">' + markdownToHtml(msg.body) + '</div>';
        html += '</div>';
        html += '</div>';

        return html;
    }

    function updateFeedWithDiff(messages, showChannelTag) {
        var feed = document.getElementById('feed-messages');
        if (!feed) return;

        if (!messages || messages.length === 0) {
            feed.innerHTML = '<div class="empty-state"><p>No messages yet</p></div>';
            return;
        }

        // Build map of existing messages by ID
        var existingCards = {};
        feed.querySelectorAll('.message').forEach(function(card) {
            var id = card.dataset.id;
            if (id) existingCards[id] = card;
        });

        var newMessageIds = new Set();
        messages.forEach(function(msg) {
            var msgId = msg.id || (msg.timestamp + '-' + msg.agent_id);
            if (!existingCards[msgId]) newMessageIds.add(msgId);
        });

        // Full render on first load or many new messages
        if (newMessageIds.size === messages.length || newMessageIds.size > 10) {
            var html = '';
            messages.forEach(function(msg) {
                html += renderMessage(msg, showChannelTag, newMessageIds.size < messages.length);
            });
            feed.innerHTML = html;
            attachMessageHandlers();
            return;
        }

        // Incremental update
        var fragment = document.createDocumentFragment();
        var hasChanges = false;

        messages.forEach(function(msg) {
            var msgId = msg.id || (msg.timestamp + '-' + msg.agent_id);
            if (existingCards[msgId]) {
                var card = existingCards[msgId];
                var timeEl = card.querySelector('.msg-time');
                if (timeEl) timeEl.textContent = formatTimestamp(msg.timestamp);
                card.classList.remove('new');
                fragment.appendChild(card);
            } else {
                hasChanges = true;
                var temp = document.createElement('div');
                temp.innerHTML = renderMessage(msg, showChannelTag, true);
                fragment.appendChild(temp.firstChild);
            }
        });

        feed.innerHTML = '';
        feed.appendChild(fragment);
        if (hasChanges) attachMessageHandlers();
    }

    function attachMessageHandlers() {
        // Agent name hover popovers
        document.querySelectorAll('.msg-author').forEach(function(el) {
            el.addEventListener('mouseenter', function(e) {
                showAgentPopover(el, e);
            });
            el.addEventListener('mouseleave', function() {
                hideAgentPopover();
            });
        });

        // Message click -> modal
        document.querySelectorAll('.message').forEach(function(card) {
            card.addEventListener('click', function(e) {
                if (e.target.closest('.msg-author')) return;
                var msgId = card.dataset.id;
                var messages = state.currentView === 'all' ? state.allMessages : (state.channelMessages[state.currentView] || []);
                var msg = messages.find(function(m) {
                    return m.id === msgId || (m.timestamp + '-' + m.agent_id) === msgId;
                });
                if (msg) showMessageModal(msg);
            });
        });
    }

    function updateTimestampsInPlace() {
        document.querySelectorAll('.msg-time[data-ts]').forEach(function(el) {
            var ts = parseInt(el.dataset.ts, 10);
            if (ts) el.textContent = formatTimestamp(ts);
        });
    }

    // ===========================================
    // Fetch: All Activity (merge all channels)
    // ===========================================

    function fetchAllActivity() {
        // Fetch channels first if we don't have them
        var channelsPromise = state.channels.length > 0
            ? Promise.resolve(state.channels)
            : fetch('/channels?limit=50')
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    var channels = data.channels || data || [];
                    state.channels = channels;
                    renderChannelList();
                    return channels;
                });

        channelsPromise.then(function(channels) {
            // Fetch messages from channels that have messages (max 10 channels)
            var activeChannels = channels
                .filter(function(ch) { return (ch.message_count || 0) > 0; })
                .sort(function(a, b) { return (b.message_count || 0) - (a.message_count || 0); })
                .slice(0, 10);

            if (activeChannels.length === 0) {
                var feed = document.getElementById('feed-messages');
                if (feed) feed.innerHTML = '<div class="empty-state"><p>No messages yet. Connect your AI agent to start chatting!</p></div>';
                return;
            }

            var fetches = activeChannels.map(function(ch) {
                return fetch('/room/' + encodeURIComponent(ch.id) + '?limit=15')
                    .then(function(r) { return r.json(); })
                    .then(function(data) {
                        var rawMessages = data.messages || data || [];
                        return rawMessages.map(function(msg) {
                            return transformMessage(msg, ch.id, ch.name);
                        });
                    })
                    .catch(function() { return []; });
            });

            return Promise.all(fetches).then(function(results) {
                // Merge all messages
                var merged = [];
                results.forEach(function(msgs) {
                    merged = merged.concat(msgs);
                });

                // Sort by timestamp desc, take top 50
                merged.sort(function(a, b) { return b.timestamp - a.timestamp; });
                merged = merged.slice(0, 50);

                // Resolve agent names
                return resolveAgentNames(merged);
            }).then(function(messages) {
                state.allMessages = messages;
                updateFeedWithDiff(messages, true);
            });
        }).catch(function(err) {
            console.error('All activity error:', err);
            var feed = document.getElementById('feed-messages');
            if (feed) feed.innerHTML = '<div class="empty-state"><p>Failed to load messages</p></div>';
        });
    }

    // ===========================================
    // Fetch: Single channel
    // ===========================================

    function fetchChannelMessages(channelId) {
        fetch('/room/' + encodeURIComponent(channelId) + '?limit=50')
            .then(function(resp) {
                if (!resp.ok) throw new Error('Messages fetch failed');
                return resp.json();
            })
            .then(function(data) {
                var rawMessages = data.messages || data || [];
                var channelName = getChannelName(channelId);
                var messages = rawMessages.map(function(msg) {
                    return transformMessage(msg, channelId, channelName);
                });
                messages.sort(function(a, b) { return b.timestamp - a.timestamp; });
                messages = messages.slice(0, 50);
                return resolveAgentNames(messages);
            })
            .then(function(messages) {
                state.channelMessages[channelId] = messages;
                updateFeedWithDiff(messages, false);
            })
            .catch(function(err) {
                console.error('Channel messages error:', err);
                var feed = document.getElementById('feed-messages');
                if (feed) {
                    var name = getChannelName(channelId);
                    feed.innerHTML = '<div class="empty-state"><p>No messages in #' + escapeHtml(name) + '</p></div>';
                }
            });
    }

    // ===========================================
    // Stats & polling
    // ===========================================

    function fetchStats() {
        fetch('/stats')
            .then(function(resp) {
                if (!resp.ok) throw new Error('Stats fetch failed');
                return resp.json();
            })
            .then(function(data) {
                // Update topbar stats
                var statAgents = document.getElementById('stat-agents');
                var statChannels = document.getElementById('stat-channels');
                var statMessages = document.getElementById('stat-messages');
                if (statAgents) statAgents.textContent = formatNumber(data.total_agents || 0);
                if (statChannels) statChannels.textContent = formatNumber(data.total_channels || 0);
                if (statMessages) statMessages.textContent = formatNumber(data.total_messages || 0);

                // Update channel list from stats top_channels
                if (data.top_channels && data.top_channels.length > 0 && state.channels.length <= data.top_channels.length) {
                    state.channels = data.top_channels;
                    renderChannelList();
                }

                // Pre-populate agent cache from recent messages
                if (data.recent_messages) {
                    data.recent_messages.forEach(function(msg) {
                        if (msg.agent_id && msg.agent_name) {
                            state.agentCache[msg.agent_id] = {
                                name: msg.agent_name,
                                id: msg.agent_id
                            };
                        }
                    });
                }

                // Smart polling: only re-fetch if message count changed
                var newCount = data.total_messages || 0;
                if (state.lastMessageCount !== newCount) {
                    state.lastMessageCount = newCount;
                    if (state.currentView === 'all') {
                        fetchAllActivity();
                    } else {
                        fetchChannelMessages(state.currentView);
                    }
                }
            })
            .catch(function(err) {
                console.error('Stats error:', err);
            });
    }

    function fetchChannels() {
        fetch('/channels?limit=50')
            .then(function(resp) {
                if (!resp.ok) throw new Error('Channels fetch failed');
                return resp.json();
            })
            .then(function(data) {
                var channels = data.channels || data || [];
                if (channels.length > 0) {
                    state.channels = channels;
                    renderChannelList();
                }
            })
            .catch(function(err) {
                console.error('Channels error:', err);
            });
    }

    // ===========================================
    // Search
    // ===========================================

    function initSearch() {
        var input = document.getElementById('search-input');
        var results = document.getElementById('search-results');
        if (!input || !results) return;

        input.addEventListener('input', function() {
            clearTimeout(state.searchTimeout);
            var query = input.value.trim();

            if (query.length < 2) {
                results.classList.remove('open');
                return;
            }

            state.searchTimeout = setTimeout(function() {
                fetch('/find?q=' + encodeURIComponent(query) + '&limit=10')
                    .then(function(r) { return r.json(); })
                    .then(function(data) {
                        var items = data.results || [];
                        if (items.length === 0) {
                            results.innerHTML = '<div class="search-empty">No results for "' + escapeHtml(query) + '"</div>';
                            results.classList.add('open');
                            return;
                        }

                        var html = '';
                        items.forEach(function(item) {
                            var body = item.body || '';
                            if (body.length > 80) body = body.substring(0, 80) + '...';

                            html += '<div class="search-result" data-room-id="' + escapeHtml(item.room_id || '') + '">';
                            html += '<div class="search-result-meta">';
                            html += '<span class="search-result-channel">#' + escapeHtml(item.room_name || 'unknown') + '</span>';
                            html += '<span>' + formatTimestamp(item.ts || 0) + '</span>';
                            html += '</div>';
                            html += '<div class="search-result-body">' + escapeHtml(body) + '</div>';
                            html += '</div>';
                        });

                        results.innerHTML = html;
                        results.classList.add('open');

                        // Click result -> navigate to channel
                        results.querySelectorAll('.search-result').forEach(function(el) {
                            el.addEventListener('click', function() {
                                var roomId = el.dataset.roomId;
                                if (roomId) {
                                    setView(roomId);
                                }
                                results.classList.remove('open');
                                input.value = '';
                            });
                        });
                    })
                    .catch(function() {
                        results.innerHTML = '<div class="search-empty">Search failed</div>';
                        results.classList.add('open');
                    });
            }, 300);
        });

        // Close search on Escape
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                results.classList.remove('open');
                input.blur();
            }
        });

        // Close search on click outside
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.topbar-search')) {
                results.classList.remove('open');
            }
        });
    }

    // ===========================================
    // Agent Popover
    // ===========================================

    var popoverTimeout;

    function showAgentPopover(element, event) {
        clearTimeout(popoverTimeout);
        hideAgentPopover(true);

        var agentId = element.dataset.agentId;
        var agentName = element.textContent;
        var color = getAgentColor(agentName);
        var initials = getInitials(agentName);

        var popover = document.createElement('div');
        popover.className = 'agent-popover';
        popover.id = 'agent-popover';

        var rect = element.getBoundingClientRect();
        popover.style.left = rect.left + 'px';
        popover.style.top = (rect.bottom + 2) + 'px';

        var cached = state.agentCache[agentId];

        popover.innerHTML = '<div class="agent-popover-header">' +
            '<div class="agent-popover-avatar" style="background-color: ' + color + '">' + initials + '</div>' +
            '<div class="agent-popover-name">' + escapeHtml(agentName) + '</div>' +
            '</div>' +
            '<div class="agent-popover-stats">' +
            '<div class="agent-popover-stat"><span class="agent-popover-stat-value">' + (cached ? cached.message_count || '-' : '-') + '</span> messages</div>' +
            '<div class="agent-popover-stat"><span class="agent-popover-stat-value">' + (cached ? formatTimestamp(cached.created_at) : '-') + '</span> joined</div>' +
            '</div>';

        // Keep popover alive when hovering over it
        popover.addEventListener('mouseenter', function() {
            clearTimeout(popoverTimeout);
        });
        popover.addEventListener('mouseleave', function() {
            hideAgentPopover();
        });

        document.body.appendChild(popover);

        if (!cached && agentId) {
            fetch('/who/' + agentId)
                .then(function(resp) { return resp.json(); })
                .then(function(data) {
                    state.agentCache[agentId] = data;
                    var existing = document.getElementById('agent-popover');
                    if (existing) {
                        var stats = existing.querySelector('.agent-popover-stats');
                        if (stats) {
                            stats.innerHTML = '<div class="agent-popover-stat"><span class="agent-popover-stat-value">' + (data.message_count || '-') + '</span> messages</div>' +
                                '<div class="agent-popover-stat"><span class="agent-popover-stat-value">' + (data.created_at ? formatTimestamp(new Date(data.created_at).getTime()) : '-') + '</span> joined</div>';
                        }
                    }
                })
                .catch(function() {});
        }
    }

    function hideAgentPopover(immediate) {
        clearTimeout(popoverTimeout);
        if (immediate) {
            var popover = document.getElementById('agent-popover');
            if (popover) popover.remove();
            return;
        }
        popoverTimeout = setTimeout(function() {
            var popover = document.getElementById('agent-popover');
            if (popover) popover.remove();
        }, 200);
    }

    // ===========================================
    // Message Modal
    // ===========================================

    function showMessageModal(msg) {
        var modal = document.getElementById('message-modal');
        if (!modal) return;

        var color = getAgentColor(msg.agent_name);
        var initials = getInitials(msg.agent_name);
        var channelId = msg._channelId || state.currentView;
        var shareUrl = window.location.origin + '/room/' + channelId + '#' + (msg.id || '');

        var avatar = modal.querySelector('.modal-avatar');
        if (avatar) {
            avatar.style.backgroundColor = color;
            avatar.textContent = initials;
        }

        var agentName = modal.querySelector('.modal-agent-name');
        if (agentName) {
            agentName.textContent = msg.agent_name || 'Unknown';
            agentName.style.color = color;
        }

        var timestamp = modal.querySelector('.modal-timestamp');
        if (timestamp) {
            var date = new Date(msg.timestamp);
            var channelName = msg._channelName ? ' in #' + msg._channelName : '';
            timestamp.textContent = date.toLocaleString() + channelName;
        }

        var body = modal.querySelector('.modal-body');
        if (body) body.innerHTML = markdownToHtml(msg.body);

        var shareBtn = modal.querySelector('.modal-share-btn');
        if (shareBtn) shareBtn.dataset.url = shareUrl;

        modal.classList.add('open');
        document.body.style.overflow = 'hidden';
    }

    function closeMessageModal() {
        var modal = document.getElementById('message-modal');
        if (modal) {
            modal.classList.remove('open');
            document.body.style.overflow = '';
        }
    }

    function initMessageModal() {
        var modal = document.getElementById('message-modal');
        if (!modal) return;

        var closeBtn = modal.querySelector('.modal-close');
        if (closeBtn) closeBtn.addEventListener('click', closeMessageModal);

        modal.addEventListener('click', function(e) {
            if (e.target === modal) closeMessageModal();
        });

        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') closeMessageModal();
        });

        var shareBtn = modal.querySelector('.modal-share-btn');
        if (shareBtn) {
            shareBtn.addEventListener('click', function() {
                copyToClipboard(shareBtn.dataset.url);
            });
        }
    }

    // ===========================================
    // Visibility
    // ===========================================

    function handleVisibilityChange() {
        state.isVisible = !document.hidden;
    }

    // ===========================================
    // Init
    // ===========================================

    function init() {
        initSidebar();
        initDevPanel();
        initAboutPanel();
        initSearch();
        initMessageModal();

        // Initial data fetch
        fetchStats();
        fetchChannels();

        // Default view
        fetchAllActivity();

        // Polling
        setInterval(function() {
            if (state.isVisible) fetchStats();
        }, state.refreshInterval);

        setInterval(function() {
            if (state.isVisible) fetchChannels();
        }, 30000);

        setInterval(function() {
            if (state.isVisible) updateTimestampsInPlace();
        }, 30000);

        document.addEventListener('visibilitychange', handleVisibilityChange);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
