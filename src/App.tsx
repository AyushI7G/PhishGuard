import React, { useState } from 'react';
import { TabId, EmailAnalysisResult, SenderAnalysisResult, UrlAnalysisResult, InboxEmail } from './types';
import { Header } from './components/Header';
import { EmailScanner } from './components/EmailScanner';
import { SenderVerifier } from './components/SenderVerifier';
import { UrlScanner } from './components/UrlScanner';
import { GmailInbox } from './components/GmailInbox';
import { Footer } from './components/Footer';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<TabId>('email');

  // Shared state for navigation and export
  const [targetSenderForVerifier, setTargetSenderForVerifier] = useState<string>('');
  const [analyzerEmailText, setAnalyzerEmailText] = useState<string>('');
  const [analyzerSender, setAnalyzerSender] = useState<string>('');

  const [lastEmailReport, setLastEmailReport] = useState<EmailAnalysisResult | null>(null);
  const [lastSenderReport, setLastSenderReport] = useState<SenderAnalysisResult | null>(null);
  const [lastUrlReport, setLastUrlReport] = useState<UrlAnalysisResult | null>(null);

  const handleJumpToSenderVerifier = (sender: string) => {
    setTargetSenderForVerifier(sender);
    setCurrentTab('sender');
  };

  const handleOpenInAnalyzer = (email: InboxEmail) => {
    const fromStr = `"${email.senderName || email.from}" <${email.from}>`;
    setAnalyzerSender(fromStr);
    setAnalyzerEmailText(`From: ${fromStr}\nSubject: ${email.subject}\n\n${email.body || email.snippet}`);
    setCurrentTab('email');
  };

  const handleExportReport = () => {
    const report = {
      generated_at: new Date().toISOString(),
      platform: 'PhishGuard',
      latest_email_analysis: lastEmailReport,
      latest_sender_analysis: lastSenderReport,
      latest_url_analysis: lastUrlReport
    };

    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `phishguard_report_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="min-h-full flex flex-col bg-slate-50 text-slate-800">
      <Header
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        onExportReport={handleExportReport}
      />

      <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 py-6">
        {currentTab === 'email' && (
          <EmailScanner
            initialEmailText={analyzerEmailText}
            initialSender={analyzerSender}
            onJumpToSenderVerifier={handleJumpToSenderVerifier}
            onAnalysisComplete={setLastEmailReport}
          />
        )}

        {currentTab === 'sender' && (
          <SenderVerifier
            initialSender={targetSenderForVerifier}
            onAnalysisComplete={setLastSenderReport}
          />
        )}

        {currentTab === 'url' && (
          <UrlScanner
            onAnalysisComplete={setLastUrlReport}
          />
        )}

        {currentTab === 'gmail' && (
          <GmailInbox
            onOpenInAnalyzer={handleOpenInAnalyzer}
          />
        )}
      </main>

      <Footer />
    </div>
  );
};

export default App;
