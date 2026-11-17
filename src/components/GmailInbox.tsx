import React, { useState, useEffect } from 'react';
import {
  Inbox,
  Search,
  Plus,
  RefreshCw,
  X,
  ExternalLink,
  ShieldCheck,
  Check
} from 'lucide-react';
import { InboxEmail, InboxStats } from '../types';

interface GmailInboxProps {
  onOpenInAnalyzer: (email: InboxEmail) => void;
}

const GOOGLE_CLIENT_ID = '436265178649-ol61us3poubkt7437s4413lop9qlb221.apps.googleusercontent.com';
const GMAIL_SCOPES = 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email';

export const GmailInbox: React.FC<GmailInboxProps> = ({ onOpenInAnalyzer }) => {
  const [emails, setEmails] = useState<InboxEmail[]>([]);
  const [stats, setStats] = useState<InboxStats>({ total: 0, phishing: 0, suspicious: 0, legitimate: 0 });
  const [loading, setLoading] = useState(false);
  const [isLiveGmail, setIsLiveGmail] = useState(false);
  const [userEmail, setUserEmail] = useState<string | null>(sessionStorage.getItem('google_user_email') || null);
  const [token, setToken] = useState<string | null>(sessionStorage.getItem('google_gmail_token') || null);

  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState<'all' | 'phishing' | 'suspicious' | 'legitimate'>('all');

  // Modals
  const [selectedEmail, setSelectedEmail] = useState<InboxEmail | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);

  // Add form fields
  const [newFrom, setNewFrom] = useState('');
  const [newSubject, setNewSubject] = useState('');
  const [newBody, setNewBody] = useState('');
  const [addingEmail, setAddingEmail] = useState(false);
  const [rescanSuccess, setRescanSuccess] = useState(false);

  const fetchInbox = async (accessToken = token) => {
    setLoading(true);
    try {
      const headers: Record<string, string> = {};
      if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
      }

      let res = await fetch('/api/inbox', { headers });

      if (res.status === 401) {
        // Token expired or invalid
        sessionStorage.removeItem('google_gmail_token');
        sessionStorage.removeItem('google_user_email');
        setToken(null);
        setUserEmail(null);
        setIsLiveGmail(false);
        res = await fetch('/api/inbox');
      }

      const data = await res.json();
      if (data.userEmail) {
        setUserEmail(data.userEmail);
        sessionStorage.setItem('google_user_email', data.userEmail);
      }
      setIsLiveGmail(Boolean(data.isLiveGmail));

      if (data.emails) {
        setEmails(data.emails);
      }
      if (data.stats) {
        setStats(data.stats);
      } else if (data.emails) {
        setStats({
          total: data.emails.length,
          phishing: data.emails.filter((e: InboxEmail) => e.classification === 'Phishing').length,
          suspicious: data.emails.filter((e: InboxEmail) => e.classification === 'Suspicious').length,
          legitimate: data.emails.filter((e: InboxEmail) => e.classification === 'Legitimate').length
        });
      }
    } catch (err) {
      console.error('Failed to load inbox data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInbox();
  }, []);

  const handleConnectGoogle = () => {
    if (window.google?.accounts?.oauth2) {
      try {
        const client = window.google.accounts.oauth2.initTokenClient({
          client_id: GOOGLE_CLIENT_ID,
          scope: GMAIL_SCOPES,
          callback: async tokenResponse => {
            if (tokenResponse.error) {
              console.error('Google OAuth error:', tokenResponse);
              alert('Authentication failed: ' + (tokenResponse.error_description || tokenResponse.error));
              return;
            }
            if (tokenResponse.access_token) {
              const newToken = tokenResponse.access_token;
              setToken(newToken);
              sessionStorage.setItem('google_gmail_token', newToken);
              await fetchInbox(newToken);
            }
          }
        });
        client.requestAccessToken({ prompt: 'consent' });
      } catch (e) {
        console.warn('Google Auth init error:', e);
      }
    } else {
      alert('Google Identity Services is initializing. Please try again in a moment.');
    }
  };

  const handleDisconnectGoogle = () => {
    if (token && window.google?.accounts?.oauth2) {
      window.google.accounts.oauth2.revoke(token, () => {});
    }
    setToken(null);
    setUserEmail(null);
    setIsLiveGmail(false);
    sessionStorage.removeItem('google_gmail_token');
    sessionStorage.removeItem('google_user_email');
    fetchInbox(null);
  };

  const handleRescan = async () => {
    setRescanSuccess(false);
    await fetchInbox();
    setRescanSuccess(true);
    setTimeout(() => setRescanSuccess(false), 2000);
  };

  const handleAddCustomEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSubject && !newBody) return;

    setAddingEmail(true);
    try {
      const res = await fetch('/api/inbox/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: newFrom || 'test-sender@domain.xyz',
          senderName: newFrom || 'Test Sender',
          subject: newSubject,
          body: newBody
        })
      });

      const data = await res.json();
      if (data.email) {
        const updated = [data.email, ...emails];
        setEmails(updated);
        setStats({
          total: updated.length,
          phishing: updated.filter(em => em.classification === 'Phishing').length,
          suspicious: updated.filter(em => em.classification === 'Suspicious').length,
          legitimate: updated.filter(em => em.classification === 'Legitimate').length
        });
        setShowAddModal(false);
        setNewFrom('');
        setNewSubject('');
        setNewBody('');
      }
    } catch (err) {
      console.error('Failed to add custom email:', err);
    } finally {
      setAddingEmail(false);
    }
  };

  // Filtering
  const filteredEmails = emails.filter(em => {
    const matchesFilter =
      activeFilter === 'all' ||
      (activeFilter === 'phishing' && em.classification === 'Phishing') ||
      (activeFilter === 'suspicious' && em.classification === 'Suspicious') ||
      (activeFilter === 'legitimate' && em.classification === 'Legitimate');

    if (!matchesFilter) return false;
    if (!searchQuery.trim()) return true;

    const q = searchQuery.toLowerCase();
    const str = `${em.from} ${em.senderName} ${em.subject} ${em.snippet} ${em.body}`.toLowerCase();
    return str.includes(q);
  });

  return (
    <div className="space-y-6">
      {/* Google OAuth Banner */}
      <div
        className={`p-4 rounded-xl border shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
          isLiveGmail || token
            ? 'border-emerald-200 bg-emerald-50/70'
            : 'border-blue-200 bg-blue-50/70'
        }`}
      >
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-slate-900">
              {isLiveGmail || token
                ? `Connected: ${userEmail || 'Your Gmail Account'}`
                : 'Connect Your Gmail Account'}
            </h3>
            {isLiveGmail || token ? (
              <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold bg-emerald-100 text-emerald-800 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                Live Gmail Active
              </span>
            ) : (
              <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold bg-blue-100 text-blue-800">
                OAuth 2.0 Ready
              </span>
            )}
          </div>
          <p className="text-xs text-slate-600">
            {isLiveGmail || token
              ? 'Real-time threat evaluation & multi-signal security verification active on your live Gmail inbox.'
              : 'Authorize read-only access to scan your real incoming Gmail inbox for phishing threats & fraudulent vectors.'}
          </p>
        </div>

        <div className="shrink-0">
          {isLiveGmail || token ? (
            <button
              onClick={handleDisconnectGoogle}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 transition shadow-xs cursor-pointer"
            >
              Disconnect
            </button>
          ) : (
            <button
              onClick={handleConnectGoogle}
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-blue-600 text-white hover:bg-blue-700 transition shadow-xs cursor-pointer"
            >
              <Inbox className="w-4 h-4" />
              <span>Connect with Google</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Inbox Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-slate-900">Inbox Threat Quarantine</h2>
            <span
              className={`text-[10px] px-2 py-0.5 rounded-md font-semibold border ${
                isLiveGmail || token
                  ? 'bg-emerald-100 text-emerald-800 border-emerald-200'
                  : 'bg-slate-100 text-slate-600 border border-slate-200'
              }`}
            >
              {isLiveGmail || token ? `Live Gmail: ${userEmail || ''}` : 'Demo Sandbox'}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            {isLiveGmail || token
              ? `Scanning live incoming messages from ${userEmail || 'Gmail'} with real-time detection.`
              : 'Live multi-signal threat evaluation & cryptographic header verification.'}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition border border-slate-200 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Test Email</span>
          </button>
          <button
            onClick={handleRescan}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition shadow-xs cursor-pointer disabled:opacity-60"
          >
            {loading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Scanning...</span>
              </>
            ) : rescanSuccess ? (
              <>
                <Check className="w-3.5 h-3.5 text-green-300" />
                <span>Scan Complete</span>
              </>
            ) : (
              <>
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Rescan</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Quick Metrics Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
          <span className="text-[11px] text-slate-500 font-medium">Total Emails</span>
          <div className="text-xl font-bold text-slate-900 mt-0.5">{stats.total}</div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
          <span className="text-[11px] text-red-600 font-medium flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
            <span>Phishing</span>
          </span>
          <div className="text-xl font-bold text-red-600 mt-0.5">{stats.phishing}</div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
          <span className="text-[11px] text-amber-600 font-medium flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
            <span>Suspicious</span>
          </span>
          <div className="text-xl font-bold text-amber-600 mt-0.5">{stats.suspicious}</div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
          <span className="text-[11px] text-blue-600 font-medium flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
            <span>Safe</span>
          </span>
          <div className="text-xl font-bold text-blue-600 mt-0.5">{stats.legitimate}</div>
        </div>
      </div>

      {/* Search & Filter */}
      <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-72">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
            <Search className="w-3.5 h-3.5" />
          </div>
          <input
            type="text"
            placeholder="Search sender, subject, keywords..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full bg-slate-50 border border-slate-200 focus:border-blue-500 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-800 placeholder-slate-400 transition"
          />
        </div>

        <div className="flex items-center gap-1.5 w-full sm:w-auto overflow-x-auto custom-scrollbar">
          {(['all', 'phishing', 'suspicious', 'legitimate'] as const).map(tab => {
            const label = tab === 'all' ? 'All' : tab === 'phishing' ? 'Phishing' : tab === 'suspicious' ? 'Suspicious' : 'Safe';
            const isActive = activeFilter === tab;
            return (
              <button
                key={tab}
                onClick={() => setActiveFilter(tab)}
                className={`px-3 py-1 rounded-lg text-xs transition whitespace-nowrap cursor-pointer ${
                  isActive
                    ? 'font-semibold bg-blue-600 text-white'
                    : 'font-medium bg-slate-100 hover:bg-slate-200 text-slate-700'
                }`}
              >
                {label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Email List */}
      <div className="space-y-2.5">
        {loading && (
          <div className="bg-white border border-slate-200 rounded-xl p-8 text-center text-slate-500 space-y-2">
            <div className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-50 text-blue-600 animate-spin">
              <RefreshCw className="w-4 h-4" />
            </div>
            <p className="text-xs font-semibold text-slate-700">
              {token ? 'Scanning live Gmail messages...' : 'Re-evaluating inbox threat signals...'}
            </p>
          </div>
        )}

        {!loading && filteredEmails.length === 0 && (
          <div className="bg-white border border-slate-200 rounded-xl p-8 text-center text-slate-500 space-y-1">
            <p className="text-xs font-semibold text-slate-700">No emails match the filter.</p>
          </div>
        )}

        {!loading &&
          filteredEmails.map(email => {
            const isPhish = email.classification === 'Phishing';
            const isSuspicious = email.classification === 'Suspicious';
            const badgeBg = isPhish
              ? 'bg-red-50 text-red-700 border-red-200'
              : isSuspicious
              ? 'bg-amber-50 text-amber-800 border-amber-200'
              : 'bg-blue-50 text-blue-700 border-blue-200';
            const badgeLabel = isPhish ? 'Phishing' : isSuspicious ? 'Suspicious' : 'Safe';

            return (
              <div
                key={email.id}
                onClick={() => setSelectedEmail(email)}
                className="bg-white p-3.5 rounded-xl border border-slate-200 hover:border-slate-300 transition cursor-pointer shadow-xs space-y-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="font-semibold text-xs text-slate-900 truncate">
                      {email.senderName || email.from}
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono hidden sm:inline truncate">
                      {email.from}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className={`text-[11px] px-2 py-0.5 rounded font-medium border ${badgeBg}`}>
                      {badgeLabel} ({Math.round(email.risk_score)}%)
                    </span>
                    <span className="text-[11px] text-slate-400">{email.date}</span>
                  </div>
                </div>
                <div className="text-xs font-medium text-slate-800 truncate">{email.subject}</div>
                <p className="text-[11px] text-slate-500 line-clamp-1">{email.snippet || email.body}</p>
              </div>
            );
          })}
      </div>

      {/* EMAIL DETAIL MODAL */}
      {selectedEmail && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-xl overflow-hidden">
            <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
              <div className="flex items-center gap-2">
                <div
                  className={`px-2.5 py-0.5 rounded text-xs font-bold uppercase text-white ${
                    selectedEmail.classification === 'Phishing'
                      ? 'bg-red-600'
                      : selectedEmail.classification === 'Suspicious'
                      ? 'bg-amber-500'
                      : 'bg-blue-600'
                  }`}
                >
                  {selectedEmail.classification.toUpperCase()}
                </div>
                <span className="text-xs text-slate-500">
                  Risk Score: <strong className="text-slate-900">{Math.round(selectedEmail.risk_score)}%</strong>
                </span>
              </div>
              <button
                onClick={() => setSelectedEmail(null)}
                className="text-slate-400 hover:text-slate-600 p-1 rounded-lg hover:bg-slate-200 transition cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 overflow-y-auto custom-scrollbar space-y-4 text-xs">
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-200 space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-slate-500 font-medium">From:</span>
                  <span className="font-mono text-slate-800 font-semibold">{selectedEmail.from}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500 font-medium">Subject:</span>
                  <span className="text-slate-900 font-semibold">{selectedEmail.subject}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500 font-medium">Date:</span>
                  <span className="text-slate-500">{selectedEmail.date}</span>
                </div>
              </div>

              <div>
                <span className="font-semibold text-slate-800 block mb-1.5">Message Body</span>
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg font-mono text-slate-700 whitespace-pre-line leading-relaxed max-h-40 overflow-y-auto custom-scrollbar">
                  {selectedEmail.body || selectedEmail.snippet}
                </div>
              </div>

              {((selectedEmail.attachment_analysis?.length ? selectedEmail.attachment_analysis : selectedEmail.attachments) || []).length > 0 && (
                <div>
                  <span className="font-semibold text-slate-800 block mb-1.5">Attachments</span>
                  <div className="space-y-1">
                    {((selectedEmail.attachment_analysis?.length ? selectedEmail.attachment_analysis : selectedEmail.attachments) || []).map((att, idx) => (
                      <div
                        key={idx}
                        className="p-2 rounded bg-slate-50 border border-slate-200 text-slate-700 flex items-center justify-between gap-2"
                      >
                        <span className="truncate font-mono">{att.filename || 'Attachment'}</span>
                        <span className="shrink-0 font-semibold">
                          {att.classification || 'Unscanned'} &middot; {Math.round(Number(att.risk_score) || 0)}%
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <span className="font-semibold text-slate-800 block mb-1.5">Identified Signals</span>
                <div className="space-y-1">
                  {(selectedEmail.detected_features || ['Standard email metrics.']).map((sig, idx) => (
                    <div
                      key={idx}
                      className="p-1.5 rounded bg-slate-50 border border-slate-200 text-slate-700 flex items-center gap-2"
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${
                          selectedEmail.classification === 'Phishing' ? 'bg-red-500' : 'bg-blue-500'
                        }`}
                      ></span>
                      <span>{sig}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="p-3 border-t border-slate-200 bg-slate-50 flex justify-between items-center">
              <button
                onClick={() => {
                  const target = selectedEmail;
                  setSelectedEmail(null);
                  onOpenInAnalyzer(target);
                }}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white transition flex items-center gap-1.5 cursor-pointer"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Open in Analyzer</span>
              </button>
              <button
                onClick={() => setSelectedEmail(null)}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-200 hover:bg-slate-300 text-slate-700 transition cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ADD TEST EMAIL MODAL */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
          <form
            onSubmit={handleAddCustomEmail}
            className="bg-white border border-slate-200 rounded-xl max-w-lg w-full p-5 shadow-xl space-y-3"
          >
            <div className="flex items-center justify-between border-b border-slate-100 pb-2">
              <h3 className="text-sm font-bold text-slate-900">Add Test Email to Inbox</h3>
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-slate-600 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2.5 text-xs">
              <div>
                <label className="block font-medium text-slate-700 mb-1">Sender Email</label>
                <input
                  type="text"
                  value={newFrom}
                  onChange={e => setNewFrom(e.target.value)}
                  placeholder="e.g. security-alert@suspicious-domain.xyz"
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 text-slate-800 focus:border-blue-500 font-mono"
                />
              </div>
              <div>
                <label className="block font-medium text-slate-700 mb-1">Subject</label>
                <input
                  type="text"
                  value={newSubject}
                  onChange={e => setNewSubject(e.target.value)}
                  placeholder="e.g. Urgent: Account Verification Required"
                  required
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 text-slate-800 focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block font-medium text-slate-700 mb-1">Message Body</label>
                <textarea
                  rows={4}
                  value={newBody}
                  onChange={e => setNewBody(e.target.value)}
                  placeholder="Type message body..."
                  required
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 text-slate-800 focus:border-blue-500 font-mono"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 text-slate-700 hover:bg-slate-200 cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={addingEmail}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white cursor-pointer disabled:opacity-60"
              >
                {addingEmail ? 'Adding & Scanning...' : 'Add & Scan'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
