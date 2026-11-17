import React from 'react';
import { ShieldCheck, Download, Mail, AtSign, Link2, Inbox } from 'lucide-react';
import { TabId } from '../types';

interface HeaderProps {
  currentTab: TabId;
  onSelectTab: (tab: TabId) => void;
  onExportReport: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentTab,
  onSelectTab,
  onExportReport
}) => {
  return (
    <header className="bg-white border-b border-slate-200 sticky top-0 z-30">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Title */}
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white font-bold shadow-sm">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <span className="font-bold text-base tracking-tight text-slate-900">PhishGuard</span>
              <span className="text-xs text-slate-500 ml-2 hidden sm:inline">Phishing Threat Detection</span>
            </div>
          </div>

          {/* Export Action */}
          <div>
            <button
              onClick={onExportReport}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition border border-slate-200 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-slate-600" />
              <span>Export Report</span>
            </button>
          </div>
        </div>

        {/* NAVIGATION TABS */}
        <nav className="flex space-x-1 sm:space-x-4 border-t border-slate-100 overflow-x-auto custom-scrollbar" aria-label="Tabs">
          <button
            onClick={() => onSelectTab('email')}
            className={`flex items-center gap-2 py-3 px-3 text-sm transition whitespace-nowrap cursor-pointer ${
              currentTab === 'email'
                ? 'font-semibold border-b-2 border-blue-600 text-blue-600'
                : 'font-medium border-b-2 border-transparent text-slate-500 hover:text-slate-900'
            }`}
          >
            <Mail className="w-4 h-4" />
            <span>Email Scanner</span>
          </button>

          <button
            onClick={() => onSelectTab('sender')}
            className={`flex items-center gap-2 py-3 px-3 text-sm transition whitespace-nowrap cursor-pointer ${
              currentTab === 'sender'
                ? 'font-semibold border-b-2 border-blue-600 text-blue-600'
                : 'font-medium border-b-2 border-transparent text-slate-500 hover:text-slate-900'
            }`}
          >
            <AtSign className="w-4 h-4" />
            <span>Sender Verifier</span>
          </button>

          <button
            onClick={() => onSelectTab('url')}
            className={`flex items-center gap-2 py-3 px-3 text-sm transition whitespace-nowrap cursor-pointer ${
              currentTab === 'url'
                ? 'font-semibold border-b-2 border-blue-600 text-blue-600'
                : 'font-medium border-b-2 border-transparent text-slate-500 hover:text-slate-900'
            }`}
          >
            <Link2 className="w-4 h-4" />
            <span>URL Scanner</span>
          </button>

          <button
            onClick={() => onSelectTab('gmail')}
            className={`flex items-center gap-2 py-3 px-3 text-sm transition whitespace-nowrap cursor-pointer ${
              currentTab === 'gmail'
                ? 'font-semibold border-b-2 border-blue-600 text-blue-600'
                : 'font-medium border-b-2 border-transparent text-slate-500 hover:text-slate-900'
            }`}
          >
            <Inbox className="w-4 h-4" />
            <span>Gmail Inbox</span>
          </button>
        </nav>
      </div>
    </header>
  );
};
