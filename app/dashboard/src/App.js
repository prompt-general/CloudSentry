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
  CircularProgress
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon
} from '@mui/icons-material';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { API_BASE_URL, fetchFindings, fetchSummary, fetchRules, websocketConnect } from './api';
import './App.css';

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

  // Load initial data
  useEffect(() => {
    loadData();
    setupWebSocket();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [findingsData, summaryData, rulesData] = await Promise.all([
        fetchFindings({ limit: 100 }),
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

  // Filter findings
  const filteredFindings = findings.filter(finding => {
    if (severityFilter !== 'all' && finding.severity !== severityFilter) return false;
    if (statusFilter !== 'all' && finding.status !== statusFilter) return false;
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