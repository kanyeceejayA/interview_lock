oes android have a guided mode android tablet? like how it is in iOS where i can use it to also prevent changing the browser tab? android 13. the problem at hand is we have a legacy php app ew are not allowed to tinker with being used for interviews https://www.ubos.org/uboshr/public/, and intermvreees are on site doing it on android 13 tablets. issue is they can change tab and google question then paste answer back. I want to block that, but cannot touch sourc ecode. so thinking of locking the tablets the way we have gjuided mode on iOS. or maybe making a webview that serves the uboshr app?? could that work? to prevent copy paste and checking other tabs?

5:20 PM

Crystallizing Android security options for interview integrity
Crystallizing Android security options for interview integrity
I'll check current options for the kiosk/lockdown piece, then lay this out. Let me search quickly.


Weighed kiosk browser and WebView solutions to lock tablet exam access
Weighed kiosk browser and WebView solutions to lock tablet exam access
Short answer: yes. Android's equivalent of iOS Guided Access is Screen Pinning (called App Pinning on some devices). Settings > Security > Screen pinning, turn it on, enable "ask for PIN before unpinning," then open the app and pin it from the recents screen. It blocks home, recents, and app switching. It's been in Android since 5.0 so it's definitely there on Android 13.

But here's the trap, and it's the thing that breaks your plan if you do the obvious version of it: pinning Chrome doesn't solve your problem. Screen pinning stops them leaving the app, but Chrome's whole job is opening tabs. They can still open a new tab inside Chrome, Google the answer, copy, switch back to the interview tab, paste. Pinning a normal browser just means they Google without ever leaving the browser. So screen pinning alone is necessary but not sufficient.

You need to remove the ability to open arbitrary tabs/URLs. Two ways, both of which serve your existing PHP app exactly as-is without touching its source:

Option 1 (fast): a kiosk browser app locked to one URL. Apps like Fully Kiosk Browser, GoBrowser, or Hexnode's kiosk browser let you set a start URL, hide the address bar, kill tab creation, and whitelist only your domain. Point it at ubos.org/uboshr/public/, whitelist that path, block everything else. Combined with screen pinning, there's literally nowhere for them to type a Google query. This is minutes of setup per tablet, good if you've got a handful of supervised on-site tablets.

Option 2 (your WebView idea, and it does work): a thin WebView wrapper app. A minimal Android app, one WebView, loads your URL, no address bar, no tabs. The part you're missing that makes this powerful: even though you can't touch the PHP source on the server, the WebView runtime is yours, so you can inject JS into the page on load. That means you can disable copy/paste without server changes:

webView.setLongClickable(false) plus overriding startActionMode to return null kills the text-selection/copy toolbar
inject CSS * { user-select: none } (but leave input fields selectable so they can still type)
inject document.addEventListener('paste', e => e.preventDefault(), true) to block pasting into answer fields
override shouldOverrideUrlLoading to reject any URL that isn't your domain, so links can't navigate them off the app
Then set it as a lock-task / kiosk app or just screen-pin it. More work than option 1, but full control and reusable across your fleet.

On copy/paste specifically, set expectations: you can reliably kill in-page selection, the context menu, and paste-into-field. Fully blocking the OS clipboard system-wide is harder. But honestly the clipboard barely matters once tab/app switching is gone, because there's no second app or tab to go fetch an answer from. Killing the switching is 90% of the fix; killing paste is the cleanup.

If this is a big fleet and you want to push config centrally instead of touching each tablet, the proper version is enrolling them in an MDM as Android Enterprise dedicated devices (COSU / lock task mode) with a single-app kiosk policy. Same effect, central control, much better than per-device PIN pinning for unsupervised use.

So: how many tablets, and are they supervised on-site the whole time, or do they go out unsupervised? That decides whether you do the quick kiosk-browser route or build the WebView wrapper.

clear one person
npx wrangler d1 execute interview-lock-log --remote --command "DELETE FROM events WHERE email='someone@example.com'"
