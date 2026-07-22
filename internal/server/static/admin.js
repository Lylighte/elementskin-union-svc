(function() {
  var apiKey = localStorage.getItem('union_admin_key') || '';
  var loginCard = document.getElementById('login-card');
  var panel = document.getElementById('panel');

  function showMsg(el, type, msg) {
    el.className = 'msg msg-' + type;
    el.textContent = msg;
  }

  function authHeaders() {
    return { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' };
  }

  function api(method, path, body) {
    return fetch(path, {
      method: method,
      headers: authHeaders(),
      body: body ? JSON.stringify(body) : undefined
    }).then(function(r) {
      if (!r.ok) return r.json().then(function(e) { throw new Error(e.detail || 'Error ' + r.status); });
      return r.json();
    });
  }

  function showPanel() {
    loginCard.classList.add('hidden');
    panel.classList.remove('hidden');
    refreshStatus();
    loadFingerprint();
  }

  if (apiKey) showPanel();

  document.getElementById('login-btn').addEventListener('click', function() {
    apiKey = document.getElementById('api-key-input').value.trim();
    if (!apiKey) return;
    localStorage.setItem('union_admin_key', apiKey);
    showMsg(document.getElementById('login-msg'), 'info', '已保存');
    showPanel();
  });

  function refreshStatus() {
    api('GET', 'api/union/admin/status').then(function(d) {
      var grid = document.getElementById('status-grid');
      grid.innerHTML = '';
      var items = [
        ['Member Key', d.member_key_configured ? '已配置' : '未配置'],
        ['Hub 连通性', d.hub_reachable ? '可达' : '不可达'],
        ['Serverlist 版本', d.serverlist_version],
        ['Privatekey 版本', d.privatekey_version],
        ['OAuth2', d.oauth2_enabled ? '已启用' : '已禁用']
      ];
      items.forEach(function(item) {
        var div = document.createElement('div');
        div.className = 'status-item';
        div.innerHTML = '<span>' + item[0] + '</span><strong>' + item[1] + '</strong>';
        grid.appendChild(div);
      });
    }).catch(function(err) {
      showMsg(document.getElementById('sync-msg'), 'err', '状态获取失败: ' + err.message);
    });
  }

  document.getElementById('refresh-status').addEventListener('click', refreshStatus);

  document.getElementById('sync-btn').addEventListener('click', function() {
    var btn = this;
    btn.disabled = true;
    btn.textContent = '同步中...';
    api('POST', 'api/union/admin/sync').then(function(d) {
      showMsg(document.getElementById('sync-msg'), 'ok', '同步完成: ' + d.synced + ' 个角色');
    }).catch(function(err) {
      showMsg(document.getElementById('sync-msg'), 'err', '同步失败: ' + err.message);
    }).finally(function() {
      btn.disabled = false;
      btn.textContent = '全站同步';
    });
  });

  function unionAction(path, name) {
    return function() {
      var btn = this;
      btn.disabled = true;
      api('POST', path).then(function(d) {
        showMsg(document.getElementById('union-msg'), 'ok', name + '成功' + (d.version ? ' (版本 ' + d.version + ')' : ''));
      }).catch(function(err) {
        showMsg(document.getElementById('union-msg'), 'err', name + '失败: ' + err.message);
      }).finally(function() {
        btn.disabled = false;
      });
    };
  }

  document.getElementById('update-list-btn').addEventListener('click', unionAction('api/union/admin/update-list', '拉取服务器列表'));
  document.getElementById('update-key-btn').addEventListener('click', unionAction('api/union/admin/update-key', '拉取私钥'));
  document.getElementById('diagnose-btn').addEventListener('click', unionAction('api/union/admin/diagnose', '诊断'));

  function loadFingerprint() {
    api('GET', 'api/union/admin/keypair-fingerprint').then(function(d) {
      document.getElementById('current-fp').textContent = d.fingerprint;
    }).catch(function() {
      document.getElementById('current-fp').textContent = '获取失败';
    });
  }

  var confirmRegen = document.getElementById('confirm-regen');
  var regenBtn = document.getElementById('regen-btn');
  confirmRegen.addEventListener('change', function() {
    regenBtn.disabled = !this.checked;
  });

  regenBtn.addEventListener('click', function() {
    var btn = this;
    btn.disabled = true;
    btn.textContent = '轮换中...';
    api('POST', 'api/union/admin/regenerate-keypair', { confirm: true }).then(function(d) {
      showMsg(document.getElementById('keypair-msg'), 'ok', '密钥已轮换: ' + d.fingerprint);
      document.getElementById('current-fp').textContent = d.fingerprint;
      confirmRegen.checked = false;
    }).catch(function(err) {
      showMsg(document.getElementById('keypair-msg'), 'err', '轮换失败: ' + err.message);
    }).finally(function() {
      btn.disabled = true;
      btn.textContent = '轮换密钥';
    });
  });

  document.getElementById('load-blacklist-btn').addEventListener('click', function() {
    api('GET', 'api/union/admin/blacklist').then(function(d) {
      var tbody = document.querySelector('#blacklist-table tbody');
      tbody.innerHTML = '';
      var items = d.items || d.data || d || [];
      if (Array.isArray(items)) {
        items.forEach(function(entry) {
          var tr = document.createElement('tr');
          var id = entry.id || entry.uuid || '';
          tr.innerHTML = '<td>' + id + '</td><td>' + JSON.stringify(entry) + '</td>';
          var td = document.createElement('td');
          var btn = document.createElement('button');
          btn.textContent = '删除';
          btn.className = 'danger';
          btn.addEventListener('click', function() {
            if (!confirm('确认删除 ' + id + '?')) return;
            api('DELETE', 'api/union/admin/blacklist/' + id).then(function() {
              tr.remove();
            }).catch(function(err) {
              alert('删除失败: ' + err.message);
            });
          });
          td.appendChild(btn);
          tr.appendChild(td);
          tbody.appendChild(tr);
        });
      }
      document.getElementById('blacklist-table').classList.remove('hidden');
    }).catch(function(err) {
      showMsg(document.getElementById('blacklist-msg'), 'err', '查询失败: ' + err.message);
    });
  });
})();
