/**
 * NEXUS 后端 API
 * 适配 Vercel + Supabase
 */

const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const JWT_SECRET   = process.env.JWT_SECRET || 'nexus_secret_2026';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '2mb' }));

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

app.post('/api/register', async (req, res) => {
    const { email, password, nickname } = req.body;
    if (!email || !password) return res.status(400).json({ error: '邮箱和密码不能为空' });
    if (password.length < 6) return res.status(400).json({ error: '密码至少6位' });
    const hash = bcrypt.hashSync(password, 10);
    const { data, error } = await supabase
        .from('users')
        .insert([{ email, password: hash, nickname: nickname || email.split('@')[0] }])
        .select().single();
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
    if (!bcrypt.compareSync(oldPassword, user.password))
        return res.status(401).json({ error: '原密码错误' });
    if (!newPassword || newPassword.length < 6)
        return res.status(400).json({ error: '新密码至少6位' });
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
