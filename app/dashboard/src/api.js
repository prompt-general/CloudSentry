import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
const WS_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000/ws';

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
});

// Findings API
export const fetchFindings = async (params = {}) => {
  const response = await api.get('/findings', { params });
  return response.data;
};

export const fetchFinding = async (id) => {
  const response = await api.get(`/findings/${id}`);
  return response.data;
};

export const updateFinding = async (id, data) => {
  const response = await api.put(`/findings/${id}`, data);
  return response.data;
};

// Summary API
export const fetchSummary = async (timeRange = '24h') => {
  const response = await api.get(`/findings/stats/summary?time_range=${timeRange}`);
  return response.data;
};

// Rules API
export const fetchRules = async () => {
  const response = await api.get('/rules');
  return response.data;
};

export const updateRule = async (id, data) => {
  const response = await api.put(`/rules/${id}`, data);
  return response.data;
};

// Audit API
export const triggerAudit = async (auditType = 'full', accountId = null) => {
  const params = new URLSearchParams({ audit_type: auditType });
  if (accountId) params.append('account_id', accountId);
  
  const response = await api.post(`/audits/trigger?${params.toString()}`);
  return response.data;
};

export const fetchAudits = async (params = {}) => {
  const response = await api.get('/audits', { params });
  return response.data;
};

// WebSocket
export const websocketConnect = (onMessage) => {
  const ws = new WebSocket(WS_URL);
  
  ws.onopen = () => {
    console.log('WebSocket connected');
    // Subscribe to findings
    ws.send(JSON.stringify({
      type: 'subscribe',
      subscriptions: ['findings']
    }));
  };
  
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (onMessage && data.rule_id) {
        onMessage(data);
      }
    } catch (err) {
      console.error('Error parsing WebSocket message:', err);
    }
  };
  
  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
  };
  
  ws.onclose = () => {
    console.log('WebSocket disconnected. Reconnecting in 5 seconds...');
    setTimeout(() => websocketConnect(onMessage), 5000);
  };
  
  return ws;
};