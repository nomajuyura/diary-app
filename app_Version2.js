// 기능 구현: 로그인, 암호화, 다이어리 관리, 자동잠금 등 모든 로직 포함

// SecurityManager: 사용자 관리, 로그인/로그아웃/회원가입/비밀번호 변경/자동잠금 등
class SecurityManager {
    constructor() {
        this.isAuthenticated = false;
        this.currentUser = null;
        this.users = JSON.parse(localStorage.getItem('diary_users') || '{}');
        this.lastUser = localStorage.getItem('last_user') || '';
        this.autoLockTimer = null;
        this.autoLockTime = 10 * 60 * 1000; // 기본 10분
        this.lastActivity = Date.now();
        this.init();
    }
    init() {
        this.setupEventListeners();
        this.updateUserList();
        this.showLoginMode();
        if (this.lastUser) {
            document.getElementById('username-input').value = this.lastUser;
        }
        ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
            document.addEventListener(event, () => this.updateActivity());
        });
        setInterval(() => this.checkAutoLock(), 10000);
    }
    setupEventListeners() {
        document.getElementById('login-btn').addEventListener('click', () => this.login());
        document.getElementById('show-signup-btn').addEventListener('click', () => this.showSignupMode());
        document.getElementById('signup-btn').addEventListener('click', () => this.signup());
        document.getElementById('show-login-btn').addEventListener('click', () => this.showLoginMode());
        document.getElementById('logout-btn').addEventListener('click', () => this.logout());
        document.getElementById('password-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.login();
        });
        document.getElementById('confirm-password').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.signup();
        });
    }
    showLoginMode() {
        document.getElementById('login-mode').style.display = 'block';
        document.getElementById('signup-mode').style.display = 'none';
        document.getElementById('login-subtitle').textContent = '로그인하세요';
        this.clearInputs();
    }
    showSignupMode() {
        document.getElementById('login-mode').style.display = 'none';
        document.getElementById('signup-mode').style.display = 'block';
        document.getElementById('login-subtitle').textContent = '새 계정을 만드세요';
        this.clearInputs();
    }
    clearInputs() {
        const inputs = ['username-input', 'password-input', 'new-username', 'new-password', 'confirm-password'];
        inputs.forEach(id => {
            const element = document.getElementById(id);
            if (element && id !== 'username-input') {
                element.value = '';
            }
        });
        document.getElementById('message-area').innerHTML = '';
    }
    async hashPassword(password, salt = '') {
        const encoder = new TextEncoder();
        const data = encoder.encode(password + salt + 'diary_salt_2024');
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    async signup() {
        const username = document.getElementById('new-username').value.trim();
        const password = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        if (!username) return this.showMessage('아이디를 입력하세요.', 'error');
        if (username.length < 4) return this.showMessage('아이디는 최소 4자 이상이어야 합니다.', 'error');
        if (!/^[a-zA-Z0-9_]+$/.test(username)) return this.showMessage('아이디는 영문, 숫자, 언더스코어만 사용 가능합니다.', 'error');
        if (this.users[username]) return this.showMessage('이미 존재하는 아이디입니다.', 'error');
        if (password.length < 4) return this.showMessage('비밀번호는 최소 4자 이상이어야 합니다.', 'error');
        if (password !== confirmPassword) return this.showMessage('비밀번호가 일치하지 않습니다.', 'error');
        const passwordHash = await this.hashPassword(password, username);
        this.users[username] = {
            passwordHash: passwordHash,
            createdAt: new Date().toISOString(),
            settings: { autoLockTime: 10 },
            encryptedData: {}
        };
        localStorage.setItem('diary_users', JSON.stringify(this.users));
        this.updateUserList();
        this.showMessage('계정이 생성되었습니다! 로그인해주세요.', 'success');
        setTimeout(() => {
            this.showLoginMode();
            document.getElementById('username-input').value = username;
        }, 1500);
    }
    async login() {
        const username = document.getElementById('username-input').value.trim();
        const password = document.getElementById('password-input').value;
        if (!username) return this.showMessage('아이디를 입력하세요.', 'error');
        if (!password) return this.showMessage('비밀번호를 입력하세요.', 'error');
        if (!this.users[username]) return this.showMessage('존재하지 않는 아이디입니다.', 'error');
        const passwordHash = await this.hashPassword(password, username);
        if (passwordHash === this.users[username].passwordHash) {
            this.currentUser = username;
            this.authenticate();
            localStorage.setItem('last_user', username);
        } else {
            this.showMessage('비밀번호가 올바르지 않습니다.', 'error');
            document.getElementById('password-input').value = '';
        }
    }
    authenticate() {
        this.isAuthenticated = true;
        document.getElementById('login-container').style.display = 'none';
        document.getElementById('app').classList.add('authenticated');
        document.getElementById('current-username').textContent = this.currentUser;
        const userSettings = this.users[this.currentUser].settings;
        this.autoLockTime = (userSettings.autoLockTime || 10) * 60 * 1000;
        this.updateActivity();
        this.startAutoLockTimer();
        if (typeof initApp === 'function') {
            initApp();
        }
    }
    logout() {
        this.isAuthenticated = false;
        this.currentUser = null;
        document.getElementById('app').classList.remove('authenticated');
        document.getElementById('login-container').style.display = 'flex';
        document.getElementById('password-input').value = '';
        document.getElementById('message-area').innerHTML = '';
        if (this.autoLockTimer) clearTimeout(this.autoLockTimer);
        this.showLoginMode();
    }
    updateActivity() {
        this.lastActivity = Date.now();
        document.getElementById('auto-lock-warning').style.display = 'none';
        if (this.isAuthenticated) this.startAutoLockTimer();
    }
    startAutoLockTimer() {
        if (this.autoLockTimer) clearTimeout(this.autoLockTimer);
        if (this.autoLockTime > 0) {
            const warningTime = this.autoLockTime * 0.9;
            setTimeout(() => {
                if (this.isAuthenticated) {
                    document.getElementById('auto-lock-warning').style.display = 'block';
                }
            }, warningTime);
            this.autoLockTimer = setTimeout(() => {
                if (this.isAuthenticated) {
                    this.logout();
                    this.showMessage('비활성 상태로 인해 자동 잠금되었습니다.', 'error');
                }
            }, this.autoLockTime);
        }
    }
    checkAutoLock() {
        if (this.isAuthenticated && this.autoLockTime > 0) {
            const timeSinceActivity = Date.now() - this.lastActivity;
            if (timeSinceActivity >= this.autoLockTime) {
                this.logout();
                this.showMessage('비활성 상태로 인해 자동 잠금되었습니다.', 'error');
            }
        }
    }
    updateUserList() {
        const userList = document.getElementById('user-list');
        const usernames = Object.keys(this.users);
        if (usernames.length === 0) {
            userList.innerHTML = '<small style="color: #999;">등록된 사용자가 없습니다</small>';
            return;
        }
        userList.innerHTML = usernames.map(username =>
            `<span class="user-chip" onclick="selectUser('${username}')">${username}</span>`
        ).join('');
    }
    async changePassword() {
        const currentPassword = document.getElementById('current-password').value;
        const newPassword = document.getElementById('new-password-change').value;
        const confirmPassword = document.getElementById('confirm-password-change').value;
        if (!currentPassword || !newPassword || !confirmPassword) return alert('모든 필드를 입력하세요.');
        const currentHash = await this.hashPassword(currentPassword, this.currentUser);
        if (currentHash !== this.users[this.currentUser].passwordHash) return alert('현재 비밀번호가 올바르지 않습니다.');
        if (newPassword.length < 4) return alert('새 비밀번호는 최소 4자 이상이어야 합니다.');
        if (newPassword !== confirmPassword) return alert('새 비밀번호가 일치하지 않습니다.');
        const newHash = await this.hashPassword(newPassword, this.currentUser);
        this.users[this.currentUser].passwordHash = newHash;
        localStorage.setItem('diary_users', JSON.stringify(this.users));
        alert('비밀번호가 성공적으로 변경되었습니다.');
        document.getElementById('current-password').value = '';
        document.getElementById('new-password-change').value = '';
        document.getElementById('confirm-password-change').value = '';
    }
    updateAutoLock() {
        const newTime = parseInt(document.getElementById('auto-lock-time').value);
        this.autoLockTime = newTime * 60 * 1000;
        this.users[this.currentUser].settings.autoLockTime = newTime;
        localStorage.setItem('diary_users', JSON.stringify(this.users));
        alert('자동 잠금 설정이 저장되었습니다.');
        if (this.isAuthenticated) this.startAutoLockTimer();
    }
    showMessage(message, type) {
        const messageArea = document.getElementById('message-area');
        messageArea.innerHTML = `<div class="${type}-message">${message}</div>`;
        setTimeout(() => { messageArea.innerHTML = ''; }, 3000);
    }
    getCurrentUser() { return this.currentUser; }
}
function selectUser(username) {
    document.getElementById('username-input').value = username;
}

// EncryptionManager: 사용자별 데이터 암호화/복호화
class EncryptionManager {
    constructor(username, password) {
        this.username = username;
        this.password = password;
    }
    async encrypt(data) {
        try {
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(JSON.stringify(data));
            const key = await this.generateKey();
            const encrypted = new Uint8Array(dataBuffer.length);
            for (let i = 0; i < dataBuffer.length; i++) {
                encrypted[i] = dataBuffer[i] ^ key[i % key.length];
            }
            return btoa(String.fromCharCode(...encrypted));
        } catch (error) {
            console.error('암호화 실패:', error);
            return JSON.stringify(data);
        }
    }
    async decrypt(encryptedData) {
        try {
            const encrypted = new Uint8Array(atob(encryptedData).split('').map(c => c.charCodeAt(0)));
            const key = await this.generateKey();
            const decrypted = new Uint8Array(encrypted.length);
            for (let i = 0; i < encrypted.length; i++) {
                decrypted[i] = encrypted[i] ^ key[i % key.length];
            }
            const decoder = new TextDecoder();
            const jsonString = decoder.decode(decrypted);
            return JSON.parse(jsonString);
        } catch (error) {
            console.error('복호화 실패:', error);
            return JSON.parse(encryptedData);
        }
    }
    async generateKey() {
        const encoder = new TextEncoder();
        const keyMaterial = encoder.encode(this.username + this.password + 'user_specific_salt');
        const hashBuffer = await crypto.subtle.digest('SHA-256', keyMaterial);
        return new Uint8Array(hashBuffer);
    }
}

// 글로벌 변수
let currentView = 'diary';
let securityManager;
let encryptionManager;
let appData = { diary: [], events: [], todos: [], projects: [] };

// 앱 초기화
document.addEventListener('DOMContentLoaded', function() {
    securityManager = new SecurityManager();
});
function initApp() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            switchView(this.dataset.view);
        });
    });
    loadUserData();
    switchView('diary');
    const currentUser = securityManager.getCurrentUser();
    const userSettings = securityManager.users[currentUser].settings;
    const autoLockTime = userSettings.autoLockTime || 10;
    document.getElementById('auto-lock-time').value = autoLockTime;
    requestNotificationPermission();
}
async function loadUserData() {
    try {
        const currentUser = securityManager.getCurrentUser();
        const password = document.getElementById('password-input').value;
        encryptionManager = new EncryptionManager(currentUser, password);
        const userData = securityManager.users[currentUser].encryptedData;
        if (userData.diary) appData.diary = await encryptionManager.decrypt(userData.diary);
        if (userData.events) appData.events = await encryptionManager.decrypt(userData.events);
        if (userData.todos) appData.todos = await encryptionManager.decrypt(userData.todos);
        if (userData.projects) appData.projects = await encryptionManager.decrypt(userData.projects);
        renderDiaryEntries();
    } catch (error) {
        console.error('사용자 데이터 로드 실패:', error);
        appData = { diary: [], events: [], todos: [], projects: [] };
    }
}
async function saveUserData(dataType, data) {
    if (!encryptionManager) return;
    try {
        const currentUser = securityManager.getCurrentUser();
        const encrypted = await encryptionManager.encrypt(data);
        if (!securityManager.users[currentUser].encryptedData) {
            securityManager.users[currentUser].encryptedData = {};
        }
        securityManager.users[currentUser].encryptedData[dataType] = encrypted;
        localStorage.setItem('diary_users', JSON.stringify(securityManager.users));
    } catch (error) {
        console.error('사용자 데이터 저장 실패:', error);
    }
}
function switchView(viewName) {
    document.querySelectorAll('.view').forEach(view => view.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(viewName + '-view').classList.add('active');
    document.querySelector(`[data-view="${viewName}"]`).classList.add('active');
    currentView = viewName;
}
// 모달
function openDiaryModal() {
    document.getElementById('modal-title').textContent = '새 일기 작성';
    document.getElementById('modal-body').innerHTML = `
        <div class="form-group">
            <label class="form-label">날짜</label>
            <input type="date" class="form-input" id="diary-date" value="${new Date().toISOString().split('T')[0]}">
        </div>
        <div class="form-group">
            <label class="form-label">기분</label>
            <select class="form-input" id="diary-mood">
                <option value="😊">😊 기쁨</option>
                <option value="😢">😢 슬픔</option>
                <option value="😐">😐 보통</option>
                <option value="😍">😍 행복</option>
                <option value="😴">😴 피곤</option>
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">제목</label>
            <input type="text" class="form-input" id="diary-title" placeholder="일기 제목을 입력하세요">
        </div>
        <div class="form-group">
            <label class="form-label">내용</label>
            <textarea class="form-input form-textarea" id="diary-content" placeholder="오늘 있었던 일을 기록해보세요..."></textarea>
        </div>
    `;
    document.getElementById('modal-container').classList.add('active');
}
function closeModal() {
    document.getElementById('modal-container').classList.remove('active');
}
async function saveModal() {
    const title = document.getElementById('modal-title').textContent;
    if (title.includes('일기')) await saveDiary();
    closeModal();
}
async function saveDiary() {
    const date = document.getElementById('diary-date').value;
    const mood = document.getElementById('diary-mood').value;
    const title = document.getElementById('diary-title').value;
    const content = document.getElementById('diary-content').value;
    if (!title || !content) {
        alert('제목과 내용을 입력해주세요.');
        return;
    }
    const newEntry = {
        id: Date.now(),
        date: date,
        title: title,
        content: content,
        mood: mood,
        author: securityManager.getCurrentUser(),
        createdAt: new Date().toISOString()
    };
    appData.diary.unshift(newEntry);
    await saveUserData('diary', appData.diary);
    renderDiaryEntries();
}
function renderDiaryEntries() {
    const container = document.getElementById('diary-entries');
    container.innerHTML = '';
    if (appData.diary.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: #666;">
                <h3>📝 첫 번째 일기를 작성해보세요!</h3>
                <p>오른쪽 상단의 "✏️ 새 일기" 버튼을 클릭하세요.</p>
            </div>
        `;
        return;
    }
    appData.diary.forEach(entry => {
        const entryDiv = document.createElement('div');
        entryDiv.className = 'diary-entry';
        entryDiv.innerHTML = `
            <div class="diary-header">
                <span class="diary-date">${formatDate(entry.date)}</span>
                <span class="diary-mood">${entry.mood}</span>
            </div>
            <h3 style="margin-bottom: 0.5rem; color: #333;">${entry.title}</h3>
            <div class="diary-content">${entry.content}</div>
            <div style="margin-top: 1rem; font-size: 0.8rem; color: #999;">
                작성자: ${entry.author || '알 수 없음'} | ${new Date(entry.createdAt).toLocaleString('ko-KR')}
            </div>
        `;
        container.appendChild(entryDiv);
    });
}
function changePassword() { securityManager.changePassword(); }
function updateAutoLock() { securityManager.updateAutoLock(); }
async function exportData() {
    try {
        const currentUser = securityManager.getCurrentUser();
        const exportData = {
            user: currentUser,
            diary: appData.diary,
            events: appData.events,
            todos: appData.todos,
            projects: appData.projects,
            exportDate: new Date().toISOString(),
            version: '2.0'
        };
        const encrypted = await encryptionManager.encrypt(exportData);
        const dataBlob = new Blob([encrypted], {type: 'text/plain'});
        const url = URL.createObjectURL(dataBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${currentUser}-diary-backup-${new Date().toISOString().split('T')[0]}.diary`;
        a.click();
        URL.revokeObjectURL(url);
        alert(`${currentUser}님의 데이터가 암호화되어 내보내기되었습니다.`);
    } catch (error) {
        alert('데이터 내보내기에 실패했습니다.');
        console.error(error);
    }
}
async function importData(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async function(e) {
        try {
            const decryptedData = await encryptionManager.decrypt(e.target.result);
            if (!decryptedData.user) throw new Error('올바르지 않은 파일 형식입니다.');
            const currentUser = securityManager.getCurrentUser();
            if (decryptedData.user !== currentUser) {
                const confirmImport = confirm(
                    `이 파일은 "${decryptedData.user}"님의 데이터입니다.\n현재 로그인한 "${currentUser}"님의 계정에 가져오시겠습니까?`
                );
                if (!confirmImport) return;
            }
            const confirmMerge = confirm('기존 데이터와 병합하시겠습니까? (취소를 누르면 기존 데이터를 덮어씁니다)');
            if (confirmMerge) {
                appData.diary = [...appData.diary, ...(decryptedData.diary || [])];
                appData.events = [...appData.events, ...(decryptedData.events || [])];
                appData.todos = [...appData.todos, ...(decryptedData.todos || [])];
                appData.projects = [...appData.projects, ...(decryptedData.projects || [])];
            } else {
                appData = {
                    diary: decryptedData.diary || [],
                    events: decryptedData.events || [],
                    todos: decryptedData.todos || [],
                    projects: decryptedData.projects || []
                };
            }
            if (confirmMerge && decryptedData.user !== currentUser) {
                appData.diary.forEach(entry => {
                    if (!entry.author) entry.author = decryptedData.user;
                });
            }
            await saveUserData('diary', appData.diary);
            await saveUserData('events', appData.events);
            await saveUserData('todos', appData.todos);
            await saveUserData('projects', appData.projects);
            renderDiaryEntries();
            alert('데이터를 성공적으로 가져왔습니다!');
        } catch (error) {
            alert('파일을 읽는데 실패했습니다. 올바른 백업 파일이고 동일한 비밀번호로 암호화되었는지 확인하세요.');
            console.error(error);
        }
    };
    reader.readAsText(file);
}
function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
}
function formatDate(dateString) {
    const date = new Date(dateString);
    const options = { year: 'numeric', month: 'long', day: 'numeric', weekday: 'short' };
    return date.toLocaleDateString('ko-KR', options);
}
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('modal-container').addEventListener('click', function(e) {
        if (e.target === this) closeModal();
    });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') closeModal();
    });
});