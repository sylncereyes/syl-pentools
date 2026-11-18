import { useState, useEffect } from 'react'
import { CheckCircle } from 'lucide-react'


export function BillingTab() {
  const [subscription, setSubscription] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadSubscription()
  }, [])

  const loadSubscription = async () => {
    try {
      const res = await fetch('/api/billing/subscription', {
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` },
      })
      if (res.ok) {
        const data = await res.json()
        setSubscription(data)
      }
    } catch (e) {
      console.error('Failed to load subscription:', e)
    } finally {
      setLoading(false)
    }
  }

  const handleCheckout = async (plan: string) => {
    try {
      const res = await fetch('/api/billing/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${localStorage.getItem('access_token')}` },
        body: JSON.stringify({ plan }),
      })
      if (res.ok) {
        const data = await res.json()
        if (data.checkout_url) {
          window.location.href = data.checkout_url
        }
      } else {
        const err = await res.json()
        alert(err.detail || 'Failed to create checkout session')
      }
    } catch (e) {
      console.error('Checkout failed:', e)
    }
  }

  const handlePortal = async () => {
    try {
      const res = await fetch('/api/billing/portal', {
        method: 'POST',
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` },
      })
      if (res.ok) {
        const data = await res.json()
        if (data.portal_url) {
          window.open(data.portal_url, '_blank')
        }
      }
    } catch (e) {
      console.error('Portal failed:', e)
    }
  }

  const handleCancel = async () => {
    if (!confirm('Cancel subscription at period end?')) return
    try {
      const res = await fetch('/api/billing/subscription/cancel', {
        method: 'POST',
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` },
      })
      if (res.ok) {
        loadSubscription()
      }
    } catch (e) {
      console.error('Cancel failed:', e)
    }
  }

  const handleResume = async () => {
    try {
      const res = await fetch('/api/billing/subscription/resume', {
        method: 'POST',
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` },
      })
      if (res.ok) {
        loadSubscription()
      }
    } catch (e) {
      console.error('Resume failed:', e)
    }
  }

  if (loading) {
    return (
      <div className="space-y-6 max-w-xl">
        <div className="animate-pulse space-y-6 max-w-xl">
          <div className="bg-white border border-slate-200 rounded-xl p-5 h-40"></div>
          <div className="bg-white border border-slate-200 rounded-xl p-5 h-80"></div>
        </div>
      </div>
    )
  }

  const plan = subscription?.plan || 'free'
  const status = subscription?.subscription_status || 'active'
  const limits = subscription?.limits || {}

  return (
    <div className="space-y-6 max-w-xl">
      <Section title="Current Plan" description={plan === 'free' ? 'Free Edition' : `${plan.charAt(0).toUpperCase() + plan.slice(1)} Edition`}>
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h4 className="font-semibold text-slate-900">{plan === 'free' ? 'Free Edition' : `${plan.charAt(0).toUpperCase() + plan.slice(1)} Edition`}</h4>
              <p className="text-sm text-slate-500">
                {limits.assets ? `${limits.assets === -1 ? 'Unlimited' : limits.assets} assets` : '5 assets'} per cycle • 
                {limits.concurrent_scans ? `${limits.concurrent_scans === -1 ? 'Unlimited' : limits.concurrent_scans} concurrent scans` : '2 concurrent scans'}
              </p>
            </div>
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${status === 'active' ? 'bg-green-100 text-green-700' : status === 'past_due' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-700'}`}>
              {status === 'active' ? 'Active' : status === 'past_due' ? 'Past Due' : status === 'canceled' ? 'Canceled' : 'Inactive'}
            </span>
          </div>
          <div className="grid grid-cols-3 gap-4 text-center">
            <div className="bg-white p-4 rounded-lg border border-slate-200">
              <p className="text-2xl font-bold text-slate-900">{limits.assets === -1 ? '∞' : `${limits.assets || 5} / ${limits.assets === -1 ? '∞' : limits.assets || 100}`}</p>
              <p className="text-xs text-slate-500">Assets Used</p>
            </div>
            <div className="bg-white p-4 rounded-lg border border-slate-200">
              <p className="text-2xl font-bold text-slate-900">{limits.concurrent_scans === -1 ? '∞' : `${limits.concurrent_scans || 0} / ${limits.concurrent_scans === -1 ? '∞' : limits.concurrent_scans || 2}`}</p>
              <p className="text-xs text-slate-500">Running Scans</p>
            </div>
            <div className="bg-white p-4 rounded-lg border border-slate-200">
              <p className="text-2xl font-bold text-slate-900">{subscription?.current_period_end ? new Date(subscription.current_period_end).toLocaleDateString() : 'N/A'}</p>
              <p className="text-xs text-slate-500">Period Ends</p>
            </div>
          </div>
        </div>
        <div className="mt-4 flex gap-3">
          {plan === 'free' ? (
            <>
              <button onClick={() => handleCheckout('netscan')} className="btn-primary px-6 py-2">Upgrade Plan</button>
              <button onClick={handlePortal} className="btn-secondary px-6 py-2">Manage Billing</button>
            </>
          ) : status === 'canceled' ? (
            <button onClick={handleResume} className="btn-primary px-6 py-2">Resume Subscription</button>
          ) : (
            <>
              <button onClick={handlePortal} className="btn-primary px-6 py-2">Manage Billing</button>
              <button onClick={handleCancel} className="btn-secondary px-6 py-2">Cancel at Period End</button>
            </>
          )}
        </div>
      </Section>

      <Section title="Paid Plans" description="Unlock more assets, concurrent scans, and advanced features.">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <PlanCard name="NetScan" price="$96/mo" features={['16 assets', 'Network scanning', 'CVE detection', '2 concurrent scans']} onClick={() => handleCheckout('netscan')} />
          <PlanCard name="AppScan" price="$140/mo" features={['5 assets', 'Website scanning', 'API scanning', 'Authenticated scans']} popular onClick={() => handleCheckout('appscan')} />
          <PlanCard name="Exploit" price="$190/mo" features={['5 assets', 'All AppScan features', 'Safe exploitation', 'Proof of exploitability']} onClick={() => handleCheckout('exploit')} />
        </div>
      </Section>

      <Section title="Billing Portal" description="Manage payment methods, view invoices, and update billing details.">
        <div className="flex items-center justify-between p-4 bg-slate-50 border border-slate-200 rounded-xl">
          <div>
            <h4 className="font-semibold text-slate-900">Stripe Billing Portal</h4>
            <p className="text-sm text-slate-500">Manage payment methods, view invoice history, and update billing details.</p>
          </div>
          <button onClick={handlePortal} className="btn-primary px-4 py-2">Open Billing Portal</button>
        </div>
      </Section>

      <Section title="Usage Limits" description="Current workspace limits based on your plan.">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <LimitCard label="Assets" used={limits.assets || 5} limit={limits.assets === -1 ? 'Unlimited' : limits.assets || 100} />
          <LimitCard label="Concurrent Scans" used={limits.concurrent_scans || 0} limit={limits.concurrent_scans === -1 ? 'Unlimited' : limits.concurrent_scans || 2} />
          <LimitCard label="Scheduled Scans" used={limits.scheduled_scans || 0} limit={limits.scheduled_scans === -1 ? 'Unlimited' : limits.scheduled_scans || 10} />
          <LimitCard label="Team Members" used={limits.team_members || 3} limit={limits.team_members === -1 ? 'Unlimited' : limits.team_members || 10} />
        </div>
      </Section>
    </div>
  )
}



function Section({ title, description, children }: { title: string; description: string; children: React.ReactNode }) {
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5">
      <h4 className="font-semibold text-slate-900 mb-1">{title}</h4>
      <p className="text-sm text-slate-500 mb-6">{description}</p>
      {children}
    </div>
  )
}

function PlanCard({ name, price, features, popular, onClick }: { name: string; price: string; features: string[]; popular?: boolean; onClick?: () => void }) {
  return (
    <div className={`bg-white border-2 rounded-xl p-6 relative ${popular ? 'border-blue-500' : 'border-slate-200'} cursor-pointer hover:shadow-lg transition-shadow`} onClick={onClick}>
      {popular && <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-blue-500 text-white text-xs font-medium rounded-full">Most Popular</div>}
      <h4 className="font-bold text-slate-900 text-lg">{name}</h4>
      <p className="text-3xl font-bold text-slate-900 mt-2">{price}</p>
      <ul className="mt-4 space-y-2">
        {features.map(f => (
          <li key={f} className="flex items-center gap-2 text-sm text-slate-600"><CheckCircle size={14} className="text-green-500" /> {f}</li>
        ))}
      </ul>
      <button className={`btn-primary w-full mt-6 px-4 py-2`}>${popular ? 'Get Started' : 'Upgrade'}</button>
    </div>
  )
}

function LimitCard({ label, used, limit }: { label: string; used: number | string; limit: number | string }) {
  const percentage = typeof used === 'number' && typeof limit === 'number' && limit > 0 ? Math.min((used / limit) * 100, 100) : 0
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5">
      <div className="flex items-center justify-between mb-2">
        <span className="font-medium text-slate-900">{label}</span>
        <span className="text-sm text-slate-500 font-mono">{used} / {limit}</span>
      </div>
      <div className="h-2 bg-slate-200 rounded-full overflow-hidden">
        <div className="h-full bg-blue-500 rounded-full transition-all" style={{ width: `${percentage}%` }} />
      </div>
    </div>
  )
}

export default BillingTab