'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[char]));
  const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;
  const labels = {overview: 'Обзор', strategies: 'Стратегии', testing: 'Проверка', logs: 'Журнал', settings: 'Настройки'};
  const STANDARD_SUITE_ID = 'flowseal-standard-v1';
  const HTTP_MODES = ['HTTP', 'TLS1.2', 'TLS1.3'];
  const CHECK_MODES = [...HTTP_MODES, 'PING'];
  const LEGACY_RESULT_LABEL = 'Старая проверка · повторите Standard';
  let state = null;
  let token = null;
  let online = false;
  let closing = false;
  let settingsInitialized = false;
  let settingsDirty = false;
  let settingsRevision = 0;
  let busy = false;
  let pendingAction = '';
  let pollInFlight = false;
  let selectedId = '';
  let detailId = '';
  let filter = 'all';
  let candidates = new Set();
  let catalogSignature = '';
  let resultsSignature = '';
  let logsSignature = '';
  let reportsSignature = '';
  let detailSequence = 0;
  let timer = null;
  let previousView = null;
  let previousAutoStatus = null;
  let recommendationSignature = '';
  const motion = window.ZapretMotion;
  function setTheme(value) {
    const theme = value === 'dark-green' ? 'dark-green' : 'graphite-red';
    document.documentElement.dataset.theme = theme;
    $('theme-select').value = theme;
    try { localStorage.setItem('nerd3n-theme', theme); } catch { /* Theme still applies when storage is disabled. */ }
  }
  let savedTheme = 'graphite-red';
  try { savedTheme = localStorage.getItem('nerd3n-theme') || savedTheme; } catch { /* Use the default palette. */ }
  setTheme(savedTheme);
  $('theme-select').addEventListener('change', event => setTheme(event.target.value));

  function notify(message, error = false) {
    const entering = $('notification').hidden;
    $('notification-text').textContent = String(message);
    $('notification').classList.toggle('error', error);
    $('notification').hidden = false;
    if (entering) motion?.reveal($('notification'));
  }

  function setOnline(value) {
    online = value;
    $('backend-state').className = `backend-state ${value ? 'online' : 'offline'}`;
    $('backend-label').textContent = closing ? 'Приложение завершено' : value ? 'Приложение на связи' : 'Нет связи с приложением';
  }

  async function api(path, body) {
    const controller = new AbortController();
    const serviceRequest = path.startsWith('/api/service/');
    const timeout = setTimeout(() => controller.abort(), serviceRequest ? 90000 : 15000);
    try {
      const options = {cache: 'no-store', signal: controller.signal};
      if (body !== undefined) {
        options.method = 'POST';
        options.headers = {'Content-Type': 'application/json', 'X-Zapret-Token': token || ''};
        options.body = JSON.stringify(body);
      }
      const response = await fetch(path, options);
      let result;
      try { result = await response.json(); } catch { throw new Error('Приложение вернуло некорректный ответ.'); }
      if (!response.ok) {
        const error = new Error(typeof result.error === 'string' ? result.error : `Ошибка приложения: ${response.status}`);
        error.status = response.status;
        throw error;
      }
      return result;
    } catch (error) {
      if (error.name === 'AbortError') throw new Error(serviceRequest ? 'Операция со службой ещё может выполняться. Дождитесь обновления её состояния.' : 'Приложение не ответило за 15 секунд. Повторите действие.');
      if (error instanceof TypeError) throw new Error('Не удалось связаться с приложением. Проверьте, что ZapretByNerd3n.exe запущен.');
      throw error;
    } finally { clearTimeout(timeout); }
  }

  function externalIds() {
    return Array.isArray(state?.externalProcessIds) ? state.externalProcessIds : [];
  }

  function autoIsRunning() {
    return ['detecting', 'testing', 'confirming', 'selecting'].includes(state?.autoSetup?.status);
  }

  function detectedNetwork() {
    return state?.detectedNetwork || state?.network || {};
  }

  function serviceState() {
    const service = state?.service || {};
    const names = {1: 'stopped', 2: 'start_pending', 3: 'stop_pending', 4: 'running', 5: 'continue_pending', 6: 'pause_pending', 7: 'paused'};
    const raw = service.state ?? service.status ?? '';
    return names[raw] || String(raw).toLowerCase().replace(/^service_/, '');
  }

  function standardSuite() {
    return {id: STANDARD_SUITE_ID, name: 'Flowseal Standard', endpointCount: 17, httpChecksPerRepeat: 36, pingChecksPerRepeat: 17, ...state?.testSuite};
  }

  function standardSuiteError() {
    if (state?.testSuite?.error) return String(state.testSuite.error);
    return state?.testSuite?.id === STANDARD_SUITE_ID ? '' : 'Набор Standard ещё не загружен. Дождитесь обновления приложения.';
  }

  function stockStrategies() {
    // Flowseal All includes every upstream BAT, including its EXP strategy.
    return (state?.strategies || []).filter(strategy => !strategy.id.startsWith('experiment-'));
  }

  function buttonStates() {
    const job = state?.job || {};
    const process = state?.process || {};
    const service = state?.service || {};
    const installed = !!service.installed;
    const serviceError = !!service.error || service.status === 'error' || (service.supported && service.installed == null);
    const servicePending = serviceState().endsWith('_pending');
    const automatic = autoIsRunning();
    const working = !!job.running || automatic;
    const available = !!state && online && !!token && !busy && !closing && !state.serviceBusy && !servicePending;
    const external = externalIds().length > 0;
    const canRun = available && state.admin === true && !working && !external && !installed && !serviceError;
    const suiteError = standardSuiteError();
    const canTest = canRun && !suiteError;
    const canManageService = available && service.supported === true && state.admin === true && !working && !serviceError;
    $('start-button').disabled = !canRun || !selectedId;
    $('stop-button').disabled = !available || !process.running || working || installed;
    $('strategy-picker').disabled = !available || !state?.strategies?.length || working;
    $('test-button').disabled = !canTest || !candidates.size;
    $('standard-all-button').disabled = !canTest || !stockStrategies().length;
    $('cancel-button').disabled = !available || !working || job.cancelRequested;
    $('use-strategy-button').disabled = !available || working || !detailId;
    $('save-settings').disabled = !available || working || process.running || !settingsDirty;
    $('exit-button').disabled = !available;
    $('auto-start-button').disabled = !canTest;
    $('auto-cancel-button').disabled = !available || !automatic || job.cancelRequested;
    $('auto-cancel-button').hidden = !automatic;
    $('detect-network-button').disabled = !available || working || detectedNetwork().status === 'detecting';
    $('service-install-button').disabled = !canManageService || service.installed !== false || external || !selectedId;
    $('service-start-button').disabled = !canManageService || !installed || !service.owned || service.running || external || process.running || serviceState() !== 'stopped';
    $('service-stop-button').disabled = !canManageService || !installed || !service.owned || !service.running || process.running;
    $('service-remove-button').disabled = !canManageService || !installed || !service.owned || process.running;
    $$('[data-action="baseline"]').forEach(button => { button.disabled = !available || working || external || installed || serviceError || !!suiteError; });
    $$('[data-candidate]').forEach(input => { input.disabled = !available || working || installed || serviceError; });
    ['select-stock', 'select-experimental', 'clear-selection', 'repeats'].forEach(id => { $(id).disabled = !available || working || installed || serviceError; });
    ['provider', 'city', 'auto-setup-enabled'].forEach(id => { $(id).disabled = !available || working || process.running; });
    $('provider-verified').disabled = !available || working || process.running || !$('provider').value.trim();
    const reason = installed ? 'Удалите автозапуск, чтобы запустить стратегию на сеанс или выполнить подбор.' : serviceError ? 'Не удалось проверить службу. Дождитесь обновления состояния.' : state?.serviceBusy || servicePending ? 'Дождитесь завершения операции со службой.' : external ? 'Сначала остановите zapret, запущенный вне приложения.' : state && !state.admin ? 'Перезапустите ZapretByNerd3n.exe от имени администратора.' : working ? 'Дождитесь завершения текущей проверки.' : '';
    $('start-button').title = reason;
    $('auto-start-button').title = reason || suiteError;
    $('test-button').title = reason || suiteError || (candidates.size ? '' : 'Выберите хотя бы одну стратегию.');
    $('standard-all-button').title = reason || suiteError;
    $('test-button').querySelector('span').textContent = working ? 'Идёт проверка…' : 'Проверить выбранные';
    $('start-button').querySelector('span').textContent = process.running ? 'Перезапустить' : 'Запустить';
    if (settingsInitialized && !settingsDirty && !busy) {
      $('settings-save-state').textContent = state.serviceBusy || servicePending ? 'Дождитесь завершения операции со службой.' : process.running || working ? 'Для изменения настроек остановите стратегию и проверку.' : 'Настройки сохранены';
    }
    $('exit-button').title = installed ? 'Закрыть приложение. Установленная служба и её автозапуск сохранятся.' : 'Закрыть приложение и остановить стратегию текущего сеанса.';
    $('service-card').setAttribute('aria-busy', String(!!state?.serviceBusy || pendingAction.startsWith('/api/service/') || servicePending));
    const pendingLabels = {install: 'Устанавливаем…', start: 'Запускаем…', stop: 'Останавливаем…', remove: 'Удаляем…'};
    const defaultLabels = {install: 'Установить с автозапуском', start: 'Запустить службу', stop: 'Остановить службу', remove: 'Удалить автозапуск'};
    Object.keys(defaultLabels).forEach(action => {
      $(`service-${action}-button`).querySelector('span').textContent = pendingAction === `/api/service/${action}` ? pendingLabels[action] : defaultLabels[action];
    });
  }

  function changeView() {
    const requested = location.hash.slice(1);
    const view = Object.hasOwn(labels, requested) ? requested : 'overview';
    $$('.view').forEach(section => { section.hidden = section.id !== `view-${view}`; });
    $$('.nav-link').forEach(link => {
      const active = link.dataset.view === view;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    });
    $('breadcrumb-page').textContent = labels[view];
    document.title = `${view === 'overview' ? 'Подключение' : labels[view]} · zapret by nerd3n`;
    if (previousView && previousView !== view) motion?.reveal($(`view-${view}`));
    previousView = view;
    if (view === 'strategies' && !detailId && state?.strategies?.length) showDetail(selectedId || state.strategies[0].id);
  }

  function renderAutomatic() {
    const setup = state.autoSetup || {};
    const network = detectedNetwork();
    const job = state.job || {};
    const status = setup.status || 'pending';
    const active = autoIsRunning();
    const suiteError = standardSuiteError();
    const detected = network.status === 'detected' && !!network.provider;
    const detecting = status === 'detecting' || network.status === 'detecting';
    const recommendation = setup.recommendation || {};
    const recommendedId = recommendation.strategyId || recommendation.recommendedId;
    const recommended = (state.strategies || []).find(strategy => strategy.id === recommendedId);
    const recommendationCurrent = (job.results || []).some(result => result.strategyId === recommendedId && resultMetrics(result).success);
    const baselineReachable = status === 'baseline_reachable' || recommendation.status === 'baseline_reachable' || recommendation.bypassNotNeeded === true;
    const completed = status === 'complete' || status === 'baseline_reachable';
    const titles = {
      pending: state.autoSetupEnabled === false ? 'Автоподбор выключен' : 'Автоподбор стратегии',
      detecting: 'Определяем текущую сеть',
      blocked: 'Нужно ваше действие',
      testing: job.phase === 'baseline' ? 'Проверяем доступ без обхода' : 'Сравниваем стратегии',
      confirming: 'Перепроверяем лучший результат',
      selecting: 'Выбираем результат',
      complete: baselineReachable ? 'Адреса Standard отвечают без обхода' : 'Подбор завершён',
      baseline_reachable: 'Адреса Standard отвечают без обхода',
      disabled: 'Автоподбор выключен',
      cancelled: 'Автоподбор остановлен',
      error: 'Не удалось завершить подбор'
    };
    const reasons = {
      pending: state.autoSetupEnabled === false ? 'Подбор можно запустить вручную или включить в настройках.' : 'Приложение определит провайдера и сравнит стратегии на наборе Standard: HTTP, TLS 1.2, TLS 1.3 и отдельный Ping.',
      detecting: 'Получаем оператора текущего внешнего IP. Это может занять несколько секунд.',
      blocked: 'Проверьте права администратора и остановите другие запущенные экземпляры zapret. Затем повторите настройку.',
      testing: 'Проверяем доступ без обхода и с разными стратегиями. Соединения могут кратковременно прерываться.',
      confirming: 'Повторные запросы помогут проверить устойчивость результата. Дождитесь завершения.',
      selecting: 'Сравниваем доступность адресов и время ответа успешных запросов.',
      complete: 'Результат относится к текущей сети. Воспроизведение видео и голосовой чат проверьте в приложениях.',
      baseline_reachable: 'Ответы адресов Standard не подтверждают работу видео и голоса. Проверьте их в приложениях; необходимость обхода этим тестом не определяется.',
      disabled: 'Подбор можно запустить вручную после проверки условий.',
      cancelled: 'Незавершённый подбор не подтверждает лучшую стратегию. Его можно запустить заново.',
      error: 'Проверьте сообщение ниже и журнал приложения, затем повторите настройку.'
    };
    const statuses = {pending: 'Ожидание', detecting: 'Определение сети', blocked: 'Нужно действие', testing: 'Проверка', confirming: 'Перепроверка', selecting: 'Выбор', complete: 'Завершено', baseline_reachable: 'Исходный доступ', disabled: 'Выключен', cancelled: 'Остановлено', error: 'Ошибка'};
    $('auto-title').textContent = suiteError && !active ? 'Набор Standard недоступен' : titles[status] || 'Автоматическая настройка';
    $('auto-reason').textContent = suiteError || (baselineReachable ? reasons.baseline_reachable : setup.reason || reasons[status] || reasons.pending);
    $('auto-status').textContent = statuses[status] || status;
    $('auto-status').className = `pill ${active ? 'blue' : status === 'blocked' ? 'warning' : status === 'error' ? 'error' : completed && recommendationCurrent && !baselineReachable ? 'success' : 'neutral'}`;
    $('auto-start-button').querySelector('span').textContent = active ? 'Настройка выполняется…' : ['blocked', 'error', 'cancelled'].includes(status) ? 'Повторить настройку' : completed ? 'Подобрать заново' : 'Подобрать автоматически';
    $('auto-details-link').hidden = !(job.results?.length || completed);
    $('detected-provider').textContent = detecting ? 'Определяем провайдера' : detected ? network.provider : 'Провайдер не определён';
    const metadata = [network.asn, network.city, network.country].filter(Boolean);
    $('detected-network-meta').textContent = detected ? metadata.join(' · ') || 'Сеть определена по внешнему IP' : network.error || (network.status === 'cancelled' ? 'Определение сети остановлено.' : 'Определите сеть для отчёта и автоподбора.');
    const detectedDate = network.detectedAt ? new Date(network.detectedAt) : null;
    const detectedTime = detectedDate && !Number.isNaN(detectedDate.valueOf()) ? detectedDate.toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'}) : '';
    $('detected-status').textContent = detected ? [network.source || 'По внешнему IP', detectedTime].filter(Boolean).join(' · ') : detecting ? 'Получаем данные…' : network.status === 'unavailable' ? 'Сервис определения недоступен' : 'По внешнему IP';
    $('network-caveat').textContent = network.warning || 'При включённом VPN может определиться его провайдер.';
    $('settings-detected-provider').textContent = detected ? network.provider : detecting ? 'Определяем…' : 'Не определён';
    $('settings-detected-meta').textContent = detected ? metadata.join(' · ') || 'По внешнему IP' : 'Данные появятся после определения сети в обзоре.';
    $('detect-network-button').firstChild.textContent = detecting ? 'Определяем…' : detected ? 'Определить повторно' : 'Определить сеть';

    const stepStates = [detected ? 'complete' : detecting ? 'current' : '', completed || ['confirming', 'selecting'].includes(status) ? 'complete' : status === 'testing' ? 'current' : '', completed ? 'complete' : ['confirming', 'selecting'].includes(status) ? 'current' : ''];
    ['network', 'testing', 'recommend'].forEach((name, index) => {
      const step = $(`setup-step-${name}`);
      step.className = stepStates[index];
      if (stepStates[index] === 'current') step.setAttribute('aria-current', 'step'); else step.removeAttribute('aria-current');
      step.querySelector('.step-number').innerHTML = stepStates[index] === 'complete' ? icon('check') : String(index + 1);
    });
    $('auto-progress-area').hidden = !active || status === 'detecting';
    const current = Math.max(0, Number(job.current) || 0);
    const total = Math.max(0, Number(job.total) || 0);
    const fraction = total ? Math.min(1, current / total) : 0;
    $('auto-progress-label').textContent = status === 'confirming' ? 'Перепроверка результата' : job.phase === 'baseline' ? 'Проверка без обхода' : `Проверяем: ${job.phase || 'доступность'}`;
    const checksProgress = currentChecksProgress(job);
    $('auto-progress-count').textContent = total ? `Прогоны: ${current} из ${total}${checksProgress ? ` · в текущем: ${checksProgress.current}/${checksProgress.total}` : ''}` : 'Ожидание результатов';
    $('auto-progress-track').setAttribute('aria-valuenow', String(Math.round(fraction * 100)));
    $('auto-progress-track').setAttribute('aria-valuetext', total ? `${current} из ${total} проверок` : 'Ожидание результатов');
    motion?.progress($('auto-progress-fill'), fraction);

    const showRecommendation = completed && !!(baselineReachable || recommendedId);
    $('auto-recommendation').hidden = !showRecommendation;
    $('auto-recommendation').classList.toggle('baseline-reachable', baselineReachable || !recommendationCurrent);
    $('auto-recommendation').querySelector('use').setAttribute('href', baselineReachable || !recommendationCurrent ? '#i-info' : '#i-check');
    $('auto-recommendation-name').textContent = baselineReachable ? 'Адреса отвечают без обхода; видео и голос не проверены' : `${recommendation.name || recommended?.name || recommendedId || ''}`;
    $('auto-recommendation-reason').textContent = baselineReachable ? reasons.baseline_reachable : !recommendationCurrent ? 'Результат не подтверждён полным Standard. Повторите проверку.' : recommendation.reason || 'Результат выбран по проверкам Standard.';
    const nextRecommendation = JSON.stringify([status, recommendedId]);
    if (showRecommendation && recommended && recommendationCurrent && !baselineReachable && nextRecommendation !== recommendationSignature) {
      selectedId = recommended.id;
      $('strategy-picker').value = selectedId;
      renderSelected();
    }
    recommendationSignature = nextRecommendation;
    if (previousAutoStatus && previousAutoStatus !== status && !$('view-overview').hidden) motion?.reveal($('auto-copy'));
    previousAutoStatus = status;
  }

  function familyBadge(strategy) {
    return strategy.experimental ? `<span class="pill warning">${strategy.id.startsWith('experiment-') ? 'Доп.' : 'EXP'}</span>` : '';
  }

  function renderCatalog() {
    const strategies = state?.strategies || [];
    const signature = JSON.stringify(strategies);
    if (signature !== catalogSignature) {
      catalogSignature = signature;
      if (!strategies.some(strategy => strategy.id === selectedId)) selectedId = strategies[0]?.id || '';
      if (!strategies.some(strategy => strategy.id === detailId)) detailId = '';
      candidates = new Set([...candidates].filter(id => strategies.some(strategy => strategy.id === id)));
      $('strategy-picker').innerHTML = strategies.length ? strategies.map(strategy => `<option value="${escape(strategy.id)}">${escape(strategy.name)}${strategy.experimental ? ' · экспериментальная' : ''}</option>`).join('') : '<option value="">Нет доступных стратегий</option>';
      $('strategy-picker').value = selectedId;
      $('strategy-count').textContent = String(strategies.length);
      renderStrategyList();
      renderCandidates();
      if (location.hash === '#strategies' && !detailId && selectedId) showDetail(selectedId);
    }
    renderSelected();
  }

  function renderSelected() {
    const strategies = state?.strategies || [];
    const selected = strategies.find(strategy => strategy.id === selectedId);
    const active = strategies.find(strategy => strategy.id === state?.process?.strategyId);
    $('selected-strategy-description').textContent = selected?.description || state?.catalogError || 'Не удалось загрузить встроенный комплект. Подробности в журнале.';
    $('active-strategy-name').textContent = active?.name || selected?.name || 'Нет доступных стратегий';
    $('active-strategy-subtitle').textContent = state?.process?.running ? 'Работает на этом компьютере' : selected ? `${selected.experimental ? 'Экспериментальная' : 'Штатная'} конфигурация` : 'Встроенный комплект не загружен';
    $('service-selected-strategy').textContent = selected?.name || 'Сначала выберите стратегию выше';
  }

  function renderService() {
    const service = state.service || {};
    const installed = !!service.installed;
    const currentState = serviceState();
    const hasError = !!service.error || service.status === 'error' || (service.supported && service.installed == null);
    const pending = !!state.serviceBusy || currentState.endsWith('_pending');
    const labels = {stopped: 'Остановлена', start_pending: 'Запускается', stop_pending: 'Останавливается', running: 'Работает', continue_pending: 'Возобновляется', pause_pending: 'Приостанавливается', paused: 'Приостановлена'};
    $('service-status').textContent = hasError ? 'Статус недоступен' : service.supported === false ? 'Недоступна' : pending ? (currentState.endsWith('_pending') ? labels[currentState] : 'Выполняется операция') : !installed ? 'Не установлена' : labels[currentState] || 'Состояние неизвестно';
    $('service-status').className = `pill ${hasError ? 'error' : pending ? 'blue' : service.running ? 'success' : installed && !service.owned ? 'warning' : 'neutral'}`;
    $('service-strategy').textContent = installed ? service.strategyName || service.strategyId || 'Неизвестна' : 'Не установлена';
    const startType = String(service.startType ?? '').toLowerCase();
    $('service-start-type').textContent = !installed ? 'Выключен' : ['2', 'auto', 'automatic', 'auto_start', 'service_auto_start'].includes(startType) ? 'При запуске Windows' : ['3', 'manual', 'demand', 'demand_start'].includes(startType) ? 'Вручную' : ['4', 'disabled'].includes(startType) ? 'Отключён' : 'Не определён';
    $('service-pid-row').hidden = !service.pid;
    $('service-pid').textContent = service.pid ? String(service.pid) : '—';
    $('service-selection').hidden = installed;
    $('service-install-button').hidden = installed;
    $('service-installed-actions').hidden = !installed;
    $('service-path-details').hidden = !service.path;
    $('service-path').textContent = service.path || '';
    $('service-error').hidden = !hasError;
    $('service-error').textContent = service.error || (hasError ? 'Не удалось получить состояние службы. Проверьте журнал приложения.' : '');
    $('service-hint').textContent = hasError ? 'Управление недоступно, пока приложение не получит состояние службы.' : service.supported === false ? 'Управление службой доступно в Windows.' : installed && !service.owned ? 'Эта служба принадлежит другой программе. Управляйте ей в программе, где она была установлена.' : !state.admin ? 'Для управления службой закройте приложение и запустите ZapretByNerd3n.exe от имени администратора.' : pending ? 'Дождитесь завершения операции со службой.' : installed ? 'Для смены стратегии или нового подбора сначала удалите автозапуск. Остановка службы сохраняет автозапуск при следующем запуске Windows.' : externalIds().length ? 'Перед установкой остановите внешний winws в программе, где он запущен.' : state.process?.running ? 'Установка остановит стратегию текущего сеанса и запустит выбранную стратегию как службу.' : 'Будет установлена выбранная выше стратегия. Автоподбор сам не устанавливает службу.';
    $('session-mode-hint').textContent = installed ? 'Установлен автозапуск. Для сеансового запуска или подбора сначала удалите автозапуск.' : 'Обычный запуск работает до закрытия приложения.';
    $('exit-hint').textContent = installed ? service.running ? 'Служба продолжит работать после закрытия окна.' : 'Закрытие окна сохраняет состояние службы и её автозапуск.' : 'При закрытии приложения стратегия текущего сеанса остановится.';
  }

  function renderStrategyList() {
    const query = $('strategy-search').value.trim().toLocaleLowerCase('ru');
    const filtered = (state?.strategies || []).filter(strategy => {
      const added = strategy.id.startsWith('experiment-');
      const category = filter === 'all' || (filter === 'experimental' ? added : !added);
      return category && `${strategy.name} ${strategy.family}`.toLocaleLowerCase('ru').includes(query);
    });
    $('strategy-list').innerHTML = filtered.length ? filtered.map(strategy => `<button type="button" class="strategy-item ${strategy.id === detailId ? 'selected' : ''}" data-strategy="${escape(strategy.id)}" aria-pressed="${strategy.id === detailId}">${icon('sliders')}<span><strong>${escape(strategy.name)}</strong><small>${escape(strategy.family)} · ${strategy.id.startsWith('experiment-') ? 'Дополнительный вариант' : 'Flowseal'}</small></span>${familyBadge(strategy)}</button>`).join('') : `<div class="empty-catalog">${state?.strategies?.length ? 'По вашему запросу ничего не найдено.' : 'Стратегии не загружены. Проверьте журнал приложения.'}</div>`;
  }

  async function showDetail(id) {
    if (!id) return;
    detailId = id;
    const sequence = ++detailSequence;
    $$('[data-strategy]').forEach(button => {
      button.classList.toggle('selected', button.dataset.strategy === id);
      button.setAttribute('aria-pressed', String(button.dataset.strategy === id));
    });
    const strategy = state?.strategies?.find(item => item.id === id);
    $('detail-name').textContent = strategy?.name || 'Стратегия';
    $('detail-description').textContent = strategy?.description || '';
    $('detail-family').textContent = strategy?.family || '—';
    $('detail-source').textContent = strategy?.source || '—';
    $('detail-experimental').hidden = !strategy?.experimental;
    $('detail-args').textContent = 'Загрузка параметров…';
    buttonStates();
    try {
      const detail = await api(`/api/strategy?id=${encodeURIComponent(id)}`);
      if (sequence !== detailSequence) return;
      const args = detail.argv || detail.args || detail.arguments;
      $('detail-args').textContent = Array.isArray(args) ? args.map((arg, i) => i === 0 || String(arg).includes(' ') ? `"${String(arg)}"` : String(arg)).join('\n') : typeof args === 'string' ? args : 'Параметры не переданы приложением.';
    } catch (error) {
      if (sequence === detailSequence) $('detail-args').textContent = error.message;
    }
  }

  function renderCandidates() {
    const strategies = state?.strategies || [];
    $('test-candidates').innerHTML = strategies.length ? strategies.map(strategy => `<label class="candidate"><input type="checkbox" data-candidate="${escape(strategy.id)}" ${candidates.has(strategy.id) ? 'checked' : ''}><span><strong>${escape(strategy.name)}</strong><small>${escape(strategy.family)}</small></span>${familyBadge(strategy)}</label>`).join('') : '<div class="empty-catalog">Нет доступных стратегий. Проверьте журнал приложения.</div>';
    updateCandidateCount();
  }

  function updateCandidateCount() {
    $('candidate-count').textContent = `${candidates.size} выбрано`;
    buttonStates();
  }

  function applyCandidateGroup(group) {
    (state?.strategies || []).forEach(strategy => {
      const added = strategy.id.startsWith('experiment-');
      if (group === 'stock' ? !added : added) candidates.add(strategy.id);
    });
    $$('[data-candidate]').forEach(input => { input.checked = candidates.has(input.dataset.candidate); });
    updateCandidateCount();
  }

  function displayMs(value) {
    return typeof value === 'number' && Number.isFinite(value) ? `${Math.round(value).toLocaleString('ru-RU')} мс` : '—';
  }

  function count(value, fallback = 0) {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : fallback;
  }

  function isStandardResult(result) {
    return result?.suiteId === STANDARD_SUITE_ID && Array.isArray(result.checks)
      && result.checks.every(check => check && CHECK_MODES.includes(check.mode));
  }

  function checkStatus(check) {
    const status = String(check?.status || '').toUpperCase();
    if (['UNSUP', 'CANCELLED', 'SSL', 'ERROR'].includes(status)) return status;
    return status === 'OK' && check.ok === true && !check.error ? 'OK' : 'ERROR';
  }

  function resultMetrics(result) {
    if (!isStandardResult(result)) return {legacy: true};
    const checks = result.checks;
    const http = checks.filter(check => HTTP_MODES.includes(check.mode));
    const ping = checks.filter(check => check.mode === 'PING');
    const suite = standardSuite();
    const repeats = count(result.repeats) || Math.max(1, ...checks.map(check => count(check.attempt, 1)));
    const httpTotal = count(result.expectedHttp, Math.max(count(result.total), count(suite.httpChecksPerRepeat) * repeats));
    const pingTotal = count(result.expectedPing, Math.max(count(result.pingTotal), count(suite.pingChecksPerRepeat) * repeats));
    const expectedChecks = count(result.expectedChecks, httpTotal + pingTotal);
    const passed = http.filter(check => checkStatus(check) === 'OK').length;
    const pingPassed = ping.filter(check => checkStatus(check) === 'OK').length;
    const unsupported = Math.max(count(result.unsupported), http.filter(check => checkStatus(check) === 'UNSUP').length);
    const pingUnsupported = Math.max(count(result.pingUnsupported), ping.filter(check => checkStatus(check) === 'UNSUP').length);
    const cancelled = !!result.cancelled || String(result.status).toLowerCase() === 'cancelled' || checks.some(check => checkStatus(check) === 'CANCELLED');
    const error = !!result.error || String(result.status).toLowerCase() === 'error';
    const identities = new Set(checks.map(check => JSON.stringify([check.service, check.target || check.url, check.mode, check.attempt])));
    const complete = result.complete === true && !cancelled && !error && http.length === httpTotal
      && ping.length === pingTotal && checks.length === expectedChecks && identities.size === checks.length;
    const success = complete && httpTotal > 0 && passed === httpTotal && !unsupported;
    const tone = success ? 'success' : cancelled || !complete || !httpTotal || (http.length && http.every(check => checkStatus(check) === 'UNSUP')) ? 'neutral' : passed ? 'warning' : 'error';
    return {legacy: false, checks, http, ping, repeats, passed, httpTotal, pingPassed, pingTotal, unsupported, pingUnsupported, cancelled, error, complete, success, tone};
  }

  function resultOutcome(metrics) {
    if (metrics.legacy) return LEGACY_RESULT_LABEL;
    if (metrics.cancelled) return 'Остановлена';
    if (metrics.error) return 'Ошибка прогона';
    if (!metrics.complete) return 'Неполная проверка';
    if (metrics.unsupported || metrics.pingUnsupported) return 'Есть UNSUP';
    return metrics.success ? 'Адреса отвечают' : 'Завершена';
  }

  function resultRows(results) {
    return results.map(result => {
      const metrics = resultMetrics(result);
      const label = result.strategyId === 'baseline' ? 'Без обхода' : result.experimental ? 'Экспериментальная' : 'Штатная стратегия';
      return `<tr><td>${escape(result.name || result.strategyId)}<small>${label}</small></td><td><span class="pill ${metrics.legacy ? 'neutral' : metrics.tone}">${metrics.legacy ? '—' : `${metrics.passed} / ${metrics.httpTotal}`}</span></td><td><span class="pill neutral">${metrics.legacy ? '—' : `${metrics.pingPassed} / ${metrics.pingTotal}`}</span></td><td>${metrics.legacy ? '—' : `${metrics.unsupported} / ${metrics.pingUnsupported}`}</td><td>${metrics.legacy ? '—' : displayMs(result.medianMs)}</td><td class="result-outcome">${escape(resultOutcome(metrics))}</td></tr>`;
    }).join('');
  }

  function table(results) {
    return `<div class="table-scroll"><table class="results-table standard-results-table"><caption class="visually-hidden">Результаты Standard: HTTP и TLS отдельно от Ping</caption><thead><tr><th scope="col">Стратегия</th><th scope="col">HTTP / TLS</th><th scope="col">Ping</th><th scope="col">UNSUP · HTTP / Ping</th><th scope="col">Медиана HTTP</th><th scope="col">Итог прогона</th></tr></thead><tbody>${resultRows(results)}</tbody></table></div>`;
  }

  function serviceSummary(service, results) {
    const result = results.at(-1);
    if (!result) return '<span class="pill neutral">Не проверен</span><small>Запустите Standard</small>';
    const metrics = resultMetrics(result);
    if (metrics.legacy) return `<span class="pill neutral">Старая проверка</span><small>Повторите Standard</small>`;
    const checks = metrics.http.filter(check => String(check.service).toLowerCase() === service.toLowerCase());
    if (!checks.length) return '<span class="pill neutral">Нет HTTP/TLS-данных</span><small>Сервис отсутствует в результатах</small>';
    const passed = checks.filter(check => checkStatus(check) === 'OK').length;
    const success = metrics.complete && passed === checks.length;
    const tone = success ? 'success' : !metrics.complete || checks.every(check => checkStatus(check) === 'UNSUP') ? 'neutral' : passed ? 'warning' : 'error';
    const detail = !metrics.complete ? resultOutcome(metrics) : success ? 'Адреса отвечают' : checks.some(check => checkStatus(check) === 'UNSUP') ? 'Есть неподдерживаемые режимы' : 'Часть адресов не ответила';
    return `<span class="pill ${tone}">HTTP/TLS: ${passed} / ${checks.length}</span><small>${escape(detail)}</small><small>${escape(result.name || result.strategyId)}</small>`;
  }

  function checkCell(check, completed) {
    if (!check) return '<span class="check-missing">Нет результата</span>';
    const status = checkStatus(check);
    const descriptions = {OK: 'Ответ получен', ERROR: 'Ошибка', SSL: 'Ошибка TLS', UNSUP: 'Не поддерживается', CANCELLED: 'Отменено'};
    const tone = status === 'UNSUP' || status === 'CANCELLED' ? 'neutral' : status === 'OK' ? completed ? 'success' : 'neutral' : 'error';
    const code = check.mode !== 'PING' && check.httpStatus != null ? `HTTP ${escape(check.httpStatus)}` : '';
    return `<span class="pill ${tone}" title="${descriptions[status]}">${status}</span><small>${[code, displayMs(check.timeMs)].filter(Boolean).join(' · ')}</small>${check.error ? `<small class="check-error">${escape(check.error)}</small>` : status === 'UNSUP' ? '<small>Не поддерживается</small>' : ''}`;
  }

  function resultDetails(result) {
    const metrics = resultMetrics(result);
    const title = escape(result.name || result.strategyId);
    if (metrics.legacy) return `<details class="result-details"><summary>${title} — ${LEGACY_RESULT_LABEL}</summary><p class="legacy-result-note">Эти результаты получены другим набором проверок. Для сравнения HTTP, TLS 1.2, TLS 1.3 и Ping запустите Standard.</p></details>`;
    const groups = new Map();
    metrics.checks.forEach(check => {
      const key = JSON.stringify([check.service, check.target || check.url]);
      if (!groups.has(key)) groups.set(key, {name: check.target || check.url || check.service, service: check.service, url: check.url, checks: []});
      const group = groups.get(key);
      if (!group.url && check.url) group.url = check.url;
      group.checks.push(check);
    });
    const endpoints = [...groups.values()].map(group => {
      const hasHttp = group.checks.some(check => HTTP_MODES.includes(check.mode)) || /^https?:\/\//.test(group.url || '');
      const attempts = [...new Set(group.checks.map(check => count(check.attempt, 1)))].sort((a, b) => a - b);
      const rows = attempts.map(attempt => `<tr><th scope="row">${attempt}</th>${CHECK_MODES.map(mode => `<td>${!hasHttp && mode !== 'PING' ? '<span class="check-missing">—</span>' : checkCell(group.checks.find(check => check.attempt === attempt && check.mode === mode), metrics.complete)}</td>`).join('')}</tr>`).join('');
      return `<section class="endpoint-result"><div class="endpoint-heading"><h3>${escape(group.name)}</h3><p>${escape(group.service || '')}${group.url ? ` · ${escape(group.url)}` : ''}</p></div><div class="table-scroll"><table class="endpoint-table"><caption class="visually-hidden">${escape(group.name)}: ответы по режимам</caption><thead><tr><th scope="col">Повтор</th>${CHECK_MODES.map(mode => `<th scope="col">${mode}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table></div></section>`;
    }).join('');
    return `<details class="result-details"><summary>${title} — адреса и режимы · ${escape(resultOutcome(metrics))}</summary>${result.error ? `<p class="inline-error result-error">${escape(result.error)}</p>` : ''}${endpoints || '<p class="legacy-result-note">Ответы ещё не получены.</p>'}</details>`;
  }

  function renderResults() {
    const results = Array.isArray(state?.job?.results) ? state.job.results : [];
    const signature = JSON.stringify([results, state?.testSuite]);
    if (signature === resultsSignature) return;
    resultsSignature = signature;
    $('youtube-result').innerHTML = serviceSummary('YouTube', results);
    $('discord-result').innerHTML = serviceSummary('Discord', results);
    const measurements = results.map(resultMetrics).filter(metrics => !metrics.legacy);
    const sum = field => measurements.reduce((total, metrics) => total + metrics[field], 0);
    $('standard-result-totals').hidden = !measurements.length;
    $('standard-http-total').textContent = `${sum('passed')} / ${sum('httpTotal')}`;
    $('standard-ping-total').textContent = `${sum('pingPassed')} / ${sum('pingTotal')}`;
    $('standard-unsupported-total').textContent = `${sum('unsupported')} / ${sum('pingUnsupported')}`;
    if (!results.length) {
      $('overview-results').innerHTML = `<div class="empty-state">${icon('pulse')}<h3>Пока без результатов</h3><p>Сначала проверьте доступ без обхода, затем сравните стратегии.</p><button class="button secondary compact" data-action="baseline">Проверить без обхода</button></div>`;
      $('test-results').innerHTML = `<div class="empty-state">${icon('pulse')}<h3>Здесь появится сравнение</h3><p>Результаты будут добавляться по мере завершения проверок.</p></div>`;
    } else {
      $('overview-results').innerHTML = table(results.slice(-5));
      $('test-results').innerHTML = table(results) + results.map(resultDetails).join('');
    }
  }

  function currentChecksProgress(job) {
    if (!count(job.checksTotal)) return null;
    return {current: Math.min(count(job.currentCheck), job.checksTotal), total: job.checksTotal};
  }

  function renderTestSuite() {
    const suite = standardSuite();
    const error = standardSuiteError();
    $('standard-suite-name').textContent = suite.name || 'Flowseal Standard';
    $('standard-suite-meta').textContent = error ? 'Набор проверок недоступен.' : `${count(suite.endpointCount)} адресов · ${count(suite.httpChecksPerRepeat)} HTTP/TLS + ${count(suite.pingChecksPerRepeat)} Ping на каждый повтор.`;
    $('standard-all-hint').textContent = `${stockStrategies().length} штатных BAT, включая EXP · 1 повтор. Дополнительные варианты можно выбрать ниже.`;
    $('standard-suite-error').hidden = !error;
    $('standard-suite-error').textContent = error;
  }

  function renderJob() {
    const job = state?.job || {};
    const phases = {idle: 'Выберите стратегии и запустите проверку.', baseline: 'Проверяем доступ без обхода…', complete: 'Проверка завершена. Подробности — в результатах ниже.', cancelled: 'Проверка остановлена. Сохранены только выполненные запросы.', error: 'Проверка завершилась с ошибкой.'};
    $('job-status').textContent = job.cancelRequested && job.running ? 'Останавливается' : job.running ? 'Выполняется' : job.phase === 'complete' ? 'Завершена' : job.phase === 'cancelled' ? 'Остановлена' : job.error ? 'Ошибка' : 'Не запущена';
    $('job-status').className = `pill ${job.running ? 'blue' : job.error ? 'error' : 'neutral'}`;
    $('job-phase').textContent = job.cancelRequested && job.running ? 'Завершаем текущие запросы и освобождаем движок…' : phases[job.phase] || `Проверяем: ${job.phase || 'стратегия'}`;
    $('job-progress').max = Math.max(Number(job.total) || 0, 1);
    $('job-progress').value = Math.min(Number(job.current) || 0, $('job-progress').max);
    $('job-counter').textContent = `Прогоны: ${Number(job.current) || 0} из ${Number(job.total) || 0}`;
    const checksProgress = currentChecksProgress(job);
    $('job-check-counter').hidden = !checksProgress;
    $('job-check-counter').textContent = checksProgress ? `В текущем прогоне: ${checksProgress.current} из ${checksProgress.total} проверок HTTP/TLS и Ping` : '';
    $('job-error').hidden = !job.error;
    $('job-error').textContent = job.error || '';
  }

  function renderLogs(force = false) {
    const onlyErrors = $('log-errors-only').checked;
    const logs = (state?.logs || []).filter(log => !onlyErrors || ['error', 'critical'].includes(String(log.level).toLowerCase()));
    const signature = JSON.stringify(logs);
    if (signature === logsSignature && !force) return;
    logsSignature = signature;
    $('log-count').textContent = `${logs.length} событий`;
    $('log-list').innerHTML = logs.length ? [...logs].reverse().map(log => {
      let time = String(log.time || '');
      const date = new Date(time);
      if (!Number.isNaN(date.valueOf())) time = date.toLocaleTimeString('ru-RU');
      const level = String(log.level || 'info').toLowerCase();
      return `<div class="log-row"><span class="log-time">${escape(time)}</span><span class="log-level ${['error', 'warning'].includes(level) ? level : ''}">${escape(level)}</span><span class="log-message">${escape(log.message)}</span></div>`;
    }).join('') : `<div class="empty-state"><p>${onlyErrors ? 'Ошибок в текущем журнале нет.' : 'Событий пока нет.'}</p></div>`;
  }

  function renderReports() {
    const reports = state?.reports || [];
    const signature = JSON.stringify([reports, state?.lastReport]);
    if (signature === reportsSignature) return;
    reportsSignature = signature;
    const last = typeof state?.lastReport === 'string' ? state.lastReport : state?.lastReport?.name;
    $('export-report').hidden = !last;
    if (last) $('export-report').href = `/api/report?name=${encodeURIComponent(last)}`;
    $('report-history').hidden = !reports.length;
    $('report-list').innerHTML = reports.map(report => {
      const date = new Date(report.created);
      const time = Number.isNaN(date.valueOf()) ? report.created : date.toLocaleString('ru-RU');
      return `<div class="report-item"><span>${escape(report.name)}<small>${escape(time)}</small></span><a class="text-link" href="/api/report?name=${encodeURIComponent(report.name)}" download aria-label="Скачать отчёт ${escape(report.name)}">${icon('download')}JSON</a></div>`;
    }).join('');
  }

  function render() {
    if (!state) return;
    const process = state.process || {};
    $('version').textContent = `v${state.version || '—'}`;
    $('sidebar-provider').textContent = state.provider || 'Профиль сети';
    $('sidebar-city').textContent = state.city || 'Город не указан';
    $('profile-provider').textContent = state.provider || 'Провайдер не указан';
    $('profile-city').textContent = state.city || 'Город не указан';
    $('profile-verified').textContent = state.providerVerified ? 'Подтверждена вами' : state.provider ? 'Не подтверждена' : 'Не указана';
    $('profile-verified').style.color = state.providerVerified ? 'var(--green)' : state.provider ? 'var(--amber)' : 'var(--muted)';
    $('profile-admin').textContent = state.admin ? 'Есть' : 'Нет';
    $('profile-admin').style.color = state.admin ? 'var(--green)' : 'var(--amber)';
    $('profile-bundle').textContent = state.catalogError ? 'Ошибка папки' : state.strategies?.length ? 'Подключён' : 'Не подключён';
    $('profile-bundle').title = state.catalogError || state.bundlePath || '';
    $('bundle-path-display').textContent = state.bundlePath || 'Путь недоступен';
    $('bundle-app-version').textContent = state.version || 'Неизвестна';
    const additionalCount = (state.strategies || []).filter(strategy => strategy.id.startsWith('experiment-')).length;
    const stockCount = (state.strategies || []).length - additionalCount;
    $('bundle-strategy-count').textContent = state.catalogError ? 'Комплект не загружен' : `${stockCount} из Flowseal · ${additionalCount} дополнительных`;
    $('network-notice').hidden = !!state.providerVerified || !state.provider;
    $('network-notice').querySelector('strong').textContent = `Профиль ${state.provider || 'провайдера'} ещё не подтверждён`;
    $('network-notice').querySelector('p').textContent = `Автоподбор использует текущее подключение. Для отчёта по сети ${state.provider || 'нужного провайдера'} подключитесь к ней и подтвердите профиль в настройках.`;
    $('admin-notice').hidden = !!state.admin;
    $('external-process-notice').hidden = externalIds().length === 0;
    $('external-process-text').textContent = `Обнаружен внешний winws (PID ${externalIds().join(', ')}). Остановите его там, где запускали, перед запуском или проверкой стратегий. Это приложение его не останавливает.`;
    const service = state.service || {};
    const serviceProblem = service.error || (service.supported && service.installed == null);
    $('test-eligibility').hidden = state.admin && externalIds().length === 0 && !service.installed && !serviceProblem && !state.serviceBusy;
    $('test-eligibility-text').textContent = [service.installed ? 'Установлен автозапуск. Удалите его в обзоре перед любой проверкой, включая проверку без обхода.' : serviceProblem ? 'Не удалось проверить состояние службы. Дождитесь обновления состояния в обзоре.' : state.serviceBusy ? 'Дождитесь завершения операции со службой.' : '', externalIds().length ? `Остановите внешний winws (PID ${externalIds().join(', ')}) в той программе, где его запускали.` : '', !state.admin ? 'Для подбора стратегий запустите ZapretByNerd3n.exe от имени администратора. Проверка без обхода не требует повышения прав.' : ''].filter(Boolean).join(' ');
    $('process-pill').className = `pill ${process.running ? 'success' : 'neutral'}`;
    $('process-pill').innerHTML = `<span class="tiny-dot"></span>${process.running ? 'Работает' : 'Остановлена'}`;
    $('engine-status').textContent = process.running ? 'Движок работает' : 'Движок приложения не запущен';
    $('engine-dot').classList.toggle('success', !!process.running);
    $('engine-pid').textContent = process.running ? `PID ${process.pid}` : 'winws';
    if (!settingsInitialized) {
      $('provider').value = state.provider || '';
      $('city').value = state.city || '';
      $('provider-verified').checked = !!state.providerVerified;
      $('auto-setup-enabled').checked = state.autoSetupEnabled !== false;
      settingsInitialized = true;
    }
    renderCatalog();
    renderAutomatic();
    renderService();
    renderTestSuite();
    renderJob();
    renderResults();
    renderLogs();
    renderReports();
    buttonStates();
    $('last-updated').textContent = `Обновлено ${new Date().toLocaleTimeString('ru-RU')}`;
  }

  async function poll() {
    if (pollInFlight || closing) return;
    pollInFlight = true;
    try {
      if (!token) token = (await api('/api/session')).token;
      state = await api('/api/state');
      setOnline(true);
      render();
    } catch (error) {
      setOnline(false);
      buttonStates();
      if (!state) {
        $('active-strategy-subtitle').textContent = error.message;
        $('settings-save-state').textContent = 'Приложение недоступно';
      }
    } finally { pollInFlight = false; }
  }

  async function action(path, body, message) {
    if (busy || closing) return false;
    busy = true;
    pendingAction = path;
    buttonStates();
    try {
      await api(path, body);
      if (message) notify(message);
      await poll();
      return true;
    } catch (error) {
      notify(error.message, true);
      if (error.status === 403) token = null;
      await poll();
      return false;
    } finally {
      busy = false;
      pendingAction = '';
      buttonStates();
    }
  }

  $('dismiss-notification').addEventListener('click', () => { $('notification').hidden = true; });
  $('auto-start-button').addEventListener('click', () => action('/api/auto-setup', {}, 'Автонастройка запрошена. Её ход появится в обзоре.'));
  $('auto-cancel-button').addEventListener('click', () => action('/api/cancel', {}, 'Остановка автонастройки запрошена. Дождитесь завершения текущих запросов.'));
  $('detect-network-button').addEventListener('click', () => action('/api/detect-network', {}));
  window.addEventListener('hashchange', changeView);
  $('strategy-picker').addEventListener('change', (event) => { selectedId = event.target.value; renderSelected(); buttonStates(); });
  $('strategy-search').addEventListener('input', renderStrategyList);
  $$('.segmented button').forEach(button => button.addEventListener('click', () => {
    filter = button.dataset.filter;
    $$('.segmented button').forEach(item => { item.classList.toggle('active', item === button); item.setAttribute('aria-pressed', String(item === button)); });
    renderStrategyList();
  }));
  $('strategy-list').addEventListener('click', (event) => {
    const button = event.target.closest('[data-strategy]');
    if (button) showDetail(button.dataset.strategy);
  });
  $('use-strategy-button').addEventListener('click', () => {
    selectedId = detailId;
    $('strategy-picker').value = selectedId;
    renderSelected();
    buttonStates();
    location.hash = 'overview';
    changeView();
    $('strategy-picker').focus();
  });
  $('start-button').addEventListener('click', () => action('/api/start', {strategyId: selectedId}, 'Стратегия запущена. Проверьте видео и голосовой чат в приложениях.'));
  $('stop-button').addEventListener('click', () => action('/api/stop', {}, 'Движок приложения остановлен.'));
  $('service-install-button').addEventListener('click', () => action('/api/service/install', {strategyId: selectedId}, 'Служба установлена с автозапуском Windows. Она продолжит работать после закрытия приложения.'));
  $('service-start-button').addEventListener('click', () => action('/api/service/start', {}, 'Служба запущена.'));
  $('service-stop-button').addEventListener('click', () => action('/api/service/stop', {}, 'Служба остановлена. Автозапуск при следующем запуске Windows сохранён.'));
  $('service-remove-button').addEventListener('click', () => action('/api/service/remove', {}, 'Автозапуск удалён. Можно запускать стратегии на сеанс и выполнять подбор.'));
  $('test-candidates').addEventListener('change', (event) => {
    const id = event.target.dataset.candidate;
    if (!id) return;
    if (event.target.checked) candidates.add(id); else candidates.delete(id);
    updateCandidateCount();
  });
  $('select-stock').addEventListener('click', () => applyCandidateGroup('stock'));
  $('select-experimental').addEventListener('click', () => applyCandidateGroup('experimental'));
  $('clear-selection').addEventListener('click', () => { candidates.clear(); $$('[data-candidate]').forEach(input => { input.checked = false; }); updateCandidateCount(); });
  $('standard-all-button').addEventListener('click', () => {
    if ($('standard-all-button').disabled) return;
    candidates = new Set(stockStrategies().map(strategy => strategy.id));
    $('repeats').value = '1';
    renderCandidates();
    return action('/api/test', {strategyIds: [...candidates], repeats: 1}, 'Standard запущен для всех штатных BAT, по одному повтору. HTTP/TLS и Ping появятся отдельно.');
  });
  $('test-button').addEventListener('click', () => action('/api/test', {strategyIds: [...candidates], repeats: Number($('repeats').value)}, 'Проверка Standard началась. HTTP/TLS и Ping появятся отдельно.'));
  document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-action="baseline"]');
    if (!button || button.disabled) return;
    location.hash = 'testing';
    action('/api/baseline', {repeats: Number($('repeats').value)}, 'Проверяем доступ без обхода.');
  });
  $('cancel-button').addEventListener('click', () => action('/api/cancel', {}, 'Остановка запрошена. Дождитесь завершения текущих запросов.'));
  $('log-errors-only').addEventListener('change', () => renderLogs(true));
  $('settings-form').addEventListener('input', () => {
    if (!$('provider').value.trim()) $('provider-verified').checked = false;
    settingsDirty = true;
    settingsRevision += 1;
    $('settings-save-state').textContent = 'Есть несохранённые изменения';
    buttonStates();
  });
  $('settings-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!$('settings-form').reportValidity() || busy) return;
    const values = {provider: $('provider').value.trim(), city: $('city').value.trim(), providerVerified: $('provider-verified').checked, autoSetupEnabled: $('auto-setup-enabled').checked};
    const savingRevision = settingsRevision;
    const saved = await action('/api/settings', values, 'Настройки сохранены. Каталог стратегий обновлён.');
    if (saved && settingsRevision === savingRevision) {
      settingsDirty = false;
      $('settings-save-state').textContent = 'Настройки сохранены';
      buttonStates();
    }
  });
  $('exit-button').addEventListener('click', async () => {
    if (busy || closing) return;
    busy = true;
    buttonStates();
    try {
      await api('/api/exit', {});
      closing = true;
      clearInterval(timer);
      setOnline(false);
      notify(state?.service?.installed ? 'Приложение завершено. Установленная служба и её автозапуск сохраняются.' : 'Приложение завершено. Стратегия текущего сеанса остановлена.');
      $('last-updated').textContent = 'Приложение завершено';
    } catch (error) { notify(error.message, true); }
    finally { busy = false; buttonStates(); }
  });

  changeView();
  poll();
  timer = setInterval(poll, 1800);
})();
