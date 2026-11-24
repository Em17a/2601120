
(()=> {
  const SITEKEY = '0x4AAAAAAGQIgx0xGBqxjl6R';
  const gate = document.getElementById('gplay-access-gate');
  const message = document.getElementById('gplay-access-message');
  const button = document.getElementById('gplay-access-submit');
  const adult = document.getElementById('gplay-adult-confirm');
  let widgetId = null, token = '';
  const loadApp = () => {
    gate.remove();
    const script = document.createElement('script');
    script.src = '/app.js?v=turnstile-access-1';
    script.defer = true;
    document.body.appendChild(script);
  };
  const status = async () => {
    try {
      const response = await fetch('/api/access/status', { credentials: 'same-origin', cache: 'no-store' });
      const data = await response.json();
      if (response.ok && data.verified) { loadApp(); return true; }
    } catch {}
    return false;
  };
  const update = () => { button.disabled = !(adult.checked && token); button.style.opacity = button.disabled ? '.55' : '1'; };
  adult.addEventListener('change', update);
  button.addEventListener('click', async () => {
    if (!adult.checked || !token) return;
    button.disabled = true;
    message.textContent = '正在验证，请稍候…';
    try {
      const response = await fetch('/api/access/verify', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token, adultConfirmed: true })
      });
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error === 'challenge_failed' ? '验证未通过，请重新完成验证。' : '暂时无法验证，请稍后重试。');
      loadApp();
    } catch (error) {
      message.textContent = error.message || '验证失败，请重试。';
      token = '';
      if (widgetId !== null && window.turnstile) window.turnstile.reset(widgetId);
      update();
    }
  });
  status().then(verified => {
    if (verified) return;
    const script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.async = true; script.defer = true;
    script.onload = () => {
      widgetId = window.turnstile.render('#gplay-turnstile', {
        sitekey: SITEKEY, action: 'gplay_access', theme: 'dark',
        callback: value => { token = value; message.textContent = '验证完成，请确认年龄后进入。'; update(); },
        'expired-callback': () => { token = ''; update(); message.textContent = '验证已过期，请重新验证。'; },
        'error-callback': () => { token = ''; update(); message.textContent = '验证组件加载失败，请刷新页面重试。'; }
      });
      message.textContent = '请完成下方安全验证。';
    };
    script.onerror = () => { message.textContent = '安全验证加载失败，请检查网络后刷新。'; };
    document.head.appendChild(script);
  });
})();
