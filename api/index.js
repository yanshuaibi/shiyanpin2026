/**
 * NEXUS 后端 API
 * 适配 Vercel + Supabase + Resend
 */

const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();

const SUPABASE_URL  = process.env.SUPABASE_URL;
const SUPABASE_KEY  = process.env.SUPABASE_KEY;
const JWT_SECRET    = process.env.JWT_SECRET || 'nexus_secret_2026';
const RESEND_KEY    = process.env.RESEND_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '2mb' }));

const codeStore = new Map();

function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: '未登录' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'token 无效或已过期' });
    }
}

app.post('/api/send-code', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: '请输入邮箱' });
    const { data: existing } = await supabase.from('users').select('id').eq('email', email).single();
    if (existing) return res.status(409).json({ error: '该邮箱已被注册' });
    const code = String(Math.floor(100000 + Math.random() * 900000));
    codeStore.set(email, { code, expires: Date.now() + 10 * 60 * 1000 });
    try {
        const resp = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${RESEND_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                from: 'NEXUS <onboarding@resend.dev>',
                to: email,
                subject: 'NEXUS 注册验证码',
                html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#0d0d1a;border-radius:16px;"><h2 style="color:#fff;">🌌 NEXUS 验证码</h2><p style="color:#aaa;">你正在注册 NEXUS 账号，验证码为：</p><div style="font-size:40px;font-weight:900;letter-spacing:12px;color:#007aff;padding:24px 0;text-align:center;">${code}</div><p style="color:#666;font-size:13px;">验证码10分钟内有效，请勿泄露给他人。</p></div>`
            })
        });
        if (!resp.ok) throw new Error('发送失败');
        res.json({ success: true, message: '验证码已发送到你的邮箱' });
    } catch(e) {
        res.status(500).json({ error: '邮件发送失败，请稍后重试' });
    }
});

app.post('/api/register', async (req, res) => {
    const { email, password, nickname, code } = req.body;
    if (!email || !password) return res.status(400).json({ error: '邮箱和密码不能为空' });
    if (password.length < 6) return res.status(400).json({ error: '密码至少6位' });
    const stored = codeStore.get(email);
    if (!stored) return res.status(400).json({ error: '请先获取验证码' });
    if (Date.now() > stored.expires) { codeStore.delete(email); return res.status(400).json({ error: '验证码已过期，请重新获取' }); }
    if (stored.code !== code) return res.status(400).json({ error: '验证码错误' });
    codeStore.delete(email);
    const hash = bcrypt.hashSync(password, 10);
    const { data, error } = await supabase.from('users').insert([{ email, password: hash, nickname: nickname || email.split('@')[0] }]).select().single();
    if (error) {
        if (error.code === '23505') return res.status(409).json({ error: '邮箱已被注册' });
        return res.status(500).json({ error: '注册失败' });
    }
    const token = jwt.sign({ id: data.id, email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: data.id, email, nickname: data.nickname, avatar: data.avatar } });
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: '邮箱和密码不能为空' });
    const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
    if (!user || !bcrypt.compareSync(password, user.password))
        return res.status(401).json({ error: '邮箱或密码错误' });
    const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, email, nickname: user.nickname, avatar: user.avatar } });
});

app.get('/api/me', authMiddleware, async (req, res) => {
    const { data: user } = await supabase.from('users').select('id, email, nickname, avatar, created_at').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: '用户不存在' });
    res.json({ user });
});

app.put('/api/me', authMiddleware, async (req, res) => {
    const { nickname, avatar } = req.body;
    const update = {};
    if (nickname !== undefined) update.nickname = nickname;
    if (avatar  !== undefined) update.avatar   = avatar;
    if (!Object.keys(update).length) return res.status(400).json({ error: '没有要更新的字段' });
    await supabase.from('users').update(update).eq('id', req.user.id);
    res.json({ success: true });
});

app.put('/api/me/password', authMiddleware, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
    if (!bcrypt.compareSync(oldPassword, user.password)) return res.status(401).json({ error: '原密码错误' });
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: '新密码至少6位' });
    await supabase.from('users').update({ password: bcrypt.hashSync(newPassword, 10) }).eq('id', req.user.id);
    res.json({ success: true });
});

app.get('/api/recent', authMiddleware, async (req, res) => {
    const { data: list } = await supabase.from('recent_apps').select('name, href, icon, bg, visited_at').eq('user_id', req.user.id).order('visited_at', { ascending: false }).limit(8);
    res.json({ list: list || [] });
});

app.post('/api/recent', authMiddleware, async (req, res) => {
    const { name, href, icon, bg } = req.body;
    if (!name || !href) return res.status(400).json({ error: '缺少必要字段' });
    await supabase.from('recent_apps').delete().eq('user_id', req.user.id).eq('href', href);
    const { data: list } = await supabase.from('recent_apps').select('id, visited_at').eq('user_id', req.user.id).order('visited_at', { ascending: true });
    if (list && list.length >= 8) await supabase.from('recent_apps').delete().eq('id', list[0].id);
    await supabase.from('recent_apps').insert([{ user_id: req.user.id, name, href, icon: icon || '🔗', bg: bg || '#333' }]);
    res.json({ success: true });
});

app.delete('/api/recent', authMiddleware, async (req, res) => {
    await supabase.from('recent_apps').delete().eq('user_id', req.user.id);
    res.json({ success: true });
});

module.exports = app;
