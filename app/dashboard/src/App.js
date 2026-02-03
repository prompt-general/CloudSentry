import React, { useState, useEffect } from 'react';
import {
  Container,
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Avatar,
  Badge
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  ExpandMore as ExpandMoreIcon,
  AccountTree as AccountTreeIcon,
  AccountBalance as AccountBalanceIcon,
  Cloud as CloudIcon
} from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { API_BASE_URL, fetchFindings, fetchSummary, fetchRules, websocketConnect } from './api';
import './App.css';

// Add cloud provider filter component
const CloudProviderFilter = ({ cloudProvider, onCloudProviderChange }) => (
  <FormControl fullWidth size="small">
    <InputLabel>Cloud Provider</InputLabel>
    <Select
      value={cloudProvider}
      label="Cloud Provider"
      onChange={onCloudProviderChange}
    >
      <MenuItem value="all">All Clouds</MenuItem>
      <MenuItem value="aws">AWS</MenuItem>
      <MenuItem value="azure">Azure</MenuItem>
    </Select>
  </FormControl>
);

// Add cloud provider badge component
const CloudProviderBadge = ({ provider }) => {
  const colors = {
    aws: '#FF9900',
    azure: '#0078D4',
    gcp: '#34A853'
  };
  
  return (
    <Chip
      label={provider.toUpperCase()}
      size="small"
      sx={{
        backgroundColor: colors[provider] || '#757575',
        color: 'white',
        fontWeight: 'bold'
      }}
    />
  );
};

// Add account selector component
function AccountSelector({ accounts, selectedAccounts, onAccountToggle }) {
  return (
    <Paper sx={{ p: 2, mb: 3 }}>
      <Typography variant="h6" gutterBottom>
        <AccountTreeIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        AWS Accounts
      </Typography>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
        <Chip
          label="All Accounts"
          color={selectedAccounts.includes('all') ? 'primary' : 'default'}
          onClick={() => onAccountToggle('all')}
          variant={selectedAccounts.includes('all') ? 'filled' : 'outlined'}
        />
        {accounts.map(account => (
          <Chip
            key={account.id}
            label={`${account.name} (${account.id})`}
            color={selectedAccounts.includes(account.id) ? 'primary' : 'default'}
            onClick={() => onAccountToggle(account.id)}
            avatar={<Avatar>{account.name.charAt(0)}</Avatar>}
            variant={selectedAccounts.includes(account.id) ? 'filled' : 'outlined'}
          />
        ))}
      </Box>
    </Paper>
  );
}

function App() {
  const [findings, setFindings] = useState([]);
  const [summary, setSummary] = useState(null);
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [cloudProviderFilter, setCloudProviderFilter] = useState('all');
  const [accounts, setAccounts] = useState([]);
  const [selectedAccounts, setSelectedAccounts] = useState(['all']);
  const [accountSummary, setAccountSummary] = useState({});

  // Load initial data
  useEffect(() => {
    loadAccounts();
    loadData();
    setupWebSocket();
  }, []);

  const loadAccounts = async () => {
    try {
      // In production, this would call an API endpoint
      // For now, use mock data
      const mockAccounts = [
        { id: '123456789012', name: 'Production', status: 'ACTIVE' },
        { id: '234567890123', name: 'Staging', status: 'ACTIVE' },
        { id: '345678901234', name: 'Development', status: 'ACTIVE' }
      ];
      setAccounts(mockAccounts);
      
      // Load account-specific summaries
      loadAccountSummaries(mockAccounts);
    } catch (err) {
      console.error('Error loading accounts:', err);
    }
  };

  const loadAccountSummaries = async (accounts) => {
    const summaries = {};
    for (const account of accounts) {
      try {
        const response = await fetch(`${API_BASE_URL}/findings/stats/summary?account_id=${account.id}`);
        const data = await response.json();
        summaries[account.id] = data;
      } catch (err) {
        console.error(`Error loading summary for account ${account.id}:`, err);
      }
    }
    setAccountSummary(summaries);
  };

  const handleAccountToggle = (accountId) => {
    if (accountId === 'all') {
      setSelectedAccounts(['all']);
    } else {
      const newSelection = selectedAccounts.includes('all') 
        ? [accountId]
        : selectedAccounts.includes(accountId)
          ? selectedAccounts.filter(id => id !== accountId)
          : [...selectedAccounts, accountId];
      
      if (newSelection.length === 0) {
        setSelectedAccounts(['all']);
      } else {
        setSelectedAccounts(newSelection);
      }
    }
  };

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Add cloud provider filter to API params
      const apiParams = {
        limit: 100,
        ...(cloudProviderFilter !== 'all' && { cloud_provider: cloudProviderFilter }),
      };
      
      const [findingsData, summaryData, rulesData] = await Promise.all([
        fetchFindings(apiParams),
        fetchSummary('24h'),
        fetchRules()
      ]);
      setFindings(findingsData);
      setSummary(summaryData);
      setRules(rulesData);
      setError(null);
    } catch (err) {
      setError('Failed to load data. Please check if the API server is running.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const setupWebSocket = () => {
    const ws = websocketConnect((data) => {
      if (data.rule_id) {
        // New finding arrived
        setFindings(prev => [data, ...prev]);
        // Update summary counts
        if (summary) {
          setSummary(prev => ({
            ...prev,
            total: prev.total + 1,
            by_severity: {
              ...prev.by_severity,
              [data.severity]: (prev.by_severity[data.severity] || 0) + 1
            }
          }));
        }
      }
    });
  };

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleSeverityFilter = (event) => {
    setSeverityFilter(event.target.value);
    setPage(0);
  };

  const handleStatusFilter = (event) => {
    setStatusFilter(event.target.value);
    setPage(0);
  };

  const handleCloudProviderFilter = (event) => {
    setCloudProviderFilter(event.target.value);
    setPage(0);
  };

  // Filter findings
  const filteredFindings = findings.filter(finding => {
    if (severityFilter !== 'all' && finding.severity !== severityFilter) return false;
    if (statusFilter !== 'all' && finding.status !== statusFilter) return false;
    if (cloudProviderFilter !== 'all' && finding.cloud_provider !== cloudProviderFilter) return false;
    if (selectedAccounts.length > 0 && !selectedAccounts.includes('all') && !selectedAccounts.includes(finding.account_id)) return false;
    return true;
  });

  // Prepare chart data
  const severityChartData = summary ? Object.entries(summary.by_severity).map(([severity, count]) => ({
    severity,
    count
  })) : [];

  const resourceChartData = summary ? Object.entries(summary.by_resource_type).map(([type, count]) => ({
    type,
    count
  })).slice(0, 5) : [];

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL': return '#ff0000';
      case 'HIGH': return '#ff6b00';
      case 'MEDIUM': return '#ffd000';
      case 'LOW': return '#00c853';
      default: return '#757575';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'OPEN': return '#f44336';
      case 'IN_PROGRESS': return '#2196f3';
      case 'RESOLVED': return '#4caf50';
      case 'SUPPRESSED': return '#9e9e9e';
      default: return '#757575';
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress />
        <Typography variant="h6" sx={{ ml: 2 }}>Loading CloudSentry Dashboard...</Typography>
      </Box>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          CloudSentry Security Dashboard
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Real-time multi-cloud security auditing
        </Typography>
      </Box>

      {/* Cloud Provider Summary */}
      <CloudProviderSummary />

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total Findings
              </Typography>
              <Typography variant="h4" component="div">
                {summary?.total || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Critical
              </Typography>
              <Typography variant="h4" component="div" sx={{ color: '#ff0000' }}>
                {summary?.by_severity?.CRITICAL || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                High
              </Typography>
              <Typography variant="h4" component="div" sx={{ color: '#ff6b00' }}>
                {summary?.by_severity?.HIGH || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Open
              </Typography>
              <Typography variant="h4" component="div">
                {summary?.by_status?.OPEN || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Findings by Severity
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={severityChartData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ severity, percent }) => `${severity}: ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="count"
                >
                  {severityChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={getSeverityColor(entry.severity)} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Top Resource Types
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={resourceChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="type" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#8884d8" />
              </BarChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
      </Grid>

      {/* Add account selector */}
      <AccountSelector
        accounts={accounts}
        selectedAccounts={selectedAccounts}
        onAccountToggle={handleAccountToggle}
      />

      {/* Add account breakdown section */}
      {accounts.length > 0 && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          {accounts.map(account => {
            const summary = accountSummary[account.id] || {};
            return (
              <Grid item xs={12} sm={6} md={4} key={account.id}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <AccountBalanceIcon sx={{ mr: 1 }} />
                      <Typography variant="h6" component="div">
                        {account.name}
                      </Typography>
                    </Box>
                    <Typography color="text.secondary" gutterBottom>
                      {account.id}
                    </Typography>
                    <Box sx={{ mt: 2 }}>
                      <Grid container spacing={1}>
                        <Grid item xs={6}>
                          <Typography variant="body2" color="text.secondary">
                            Findings
                          </Typography>
                          <Typography variant="h6">
                            {summary.total || 0}
                          </Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="body2" color="text.secondary">
                            Critical
                          </Typography>
                          <Typography variant="h6" sx={{ color: '#ff0000' }}>
                            {summary.by_severity?.CRITICAL || 0}
                          </Typography>
                        </Grid>
                      </Grid>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}

      {/* Filters */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} sm={6} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Severity</InputLabel>
              <Select
                value={severityFilter}
                label="Severity"
                onChange={handleSeverityFilter}
              >
                <MenuItem value="all">All Severities</MenuItem>
                <MenuItem value="CRITICAL">Critical</MenuItem>
                <MenuItem value="HIGH">High</MenuItem>
                <MenuItem value="MEDIUM">Medium</MenuItem>
                <MenuItem value="LOW">Low</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Status</InputLabel>
              <Select
                value={statusFilter}
                label="Status"
                onChange={handleStatusFilter}
              >
                <MenuItem value="all">All Statuses</MenuItem>
                <MenuItem value="OPEN">Open</MenuItem>
                <MenuItem value="IN_PROGRESS">In Progress</MenuItem>
                <MenuItem value="RESOLVED">Resolved</MenuItem>
                <MenuItem value="SUPPRESSED">Suppressed</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Cloud Provider</InputLabel>
              <Select
                value={cloudProviderFilter}
                label="Cloud Provider"
                onChange={handleCloudProviderFilter}
              >
                <MenuItem value="all">All Clouds</MenuItem>
                <MenuItem value="aws">AWS</MenuItem>
                <MenuItem value="azure">Azure</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="body2" color="text.secondary">
              Showing {filteredFindings.length} findings
            </Typography>
          </Grid>
        </Grid>
      </Paper>

      {/* Findings Table */}
      <Paper sx={{ width: '100%', overflow: 'hidden' }}>
        <TableContainer sx={{ maxHeight: 500 }}>
          <Table stickyHeader size="small">
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>Cloud</TableCell>
                <TableCell>Rule</TableCell>
                <TableCell>Resource</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Account</TableCell>
                <TableCell>Region</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredFindings
                .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                .map((finding) => (
                  <TableRow key={finding.id} hover>
                    <TableCell>
                      {new Date(finding.timestamp).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <CloudProviderBadge provider={finding.cloud_provider || 'aws'} />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {finding.rule_id}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {rules.find(r => r.id === finding.rule_id)?.description || 'Unknown rule'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {finding.resource_id}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {finding.resource_type}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={finding.severity}
                        size="small"
                        sx={{
                          backgroundColor: getSeverityColor(finding.severity),
                          color: 'white',
                          fontWeight: 'bold'
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={finding.status}
                        size="small"
                        sx={{
                          backgroundColor: getStatusColor(finding.status),
                          color: 'white'
                        }}
                      />
                    </TableCell>
                    <TableCell>{finding.account_id || 'N/A'}</TableCell>
                    <TableCell>{finding.region || 'N/A'}</TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          rowsPerPageOptions={[5, 10, 25, 50]}
          component="div"
          count={filteredFindings.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </Paper>

      {/* Footer */}
      <Box sx={{ mt: 4, pt: 3, borderTop: 1, borderColor: 'divider' }}>
        <Typography variant="body2" color="text.secondary" align="center">
          CloudSentry v1.0.0 • Real-time security auditing • {new Date().toLocaleDateString()}
        </Typography>
      </Box>
    </Container>
  );
}

export default App;