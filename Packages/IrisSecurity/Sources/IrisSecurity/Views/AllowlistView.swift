import SwiftUI

/// Management UI for the AllowlistStore.
/// Lists suppressed entries with swipe-to-delete and an add form.
public struct AllowlistView: View {
  @State private var entries: [AllowlistStore.AllowlistEntry] = []
  @State private var showAdd = false

  public init() {}

  public var body: some View {
    VStack(spacing: 0) {
      header
      if entries.isEmpty {
        emptyState
      } else {
        entryList
      }
    }
    .task { await loadEntries() }
    .sheet(isPresented: $showAdd) {
      AddAllowlistSheet { await loadEntries() }
    }
  }

  private var header: some View {
    HStack {
      VStack(alignment: .leading, spacing: 2) {
        Text("Allowlist")
          .font(.system(size: 16, weight: .bold)).foregroundColor(.white)
        Text("\(entries.count) entries")
          .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
      }
      Spacer()
      Button(action: { showAdd = true }) {
        Image(systemName: "plus.circle.fill").foregroundColor(.cyan)
      }.buttonStyle(.plain)
    }.padding(20)
  }

  private var entryList: some View {
    ThemedScrollView {
      LazyVStack(alignment: .leading, spacing: 2) {
        ForEach(entries) { entry in
          AllowlistEntryRow(entry: entry) {
            Task {
              await AllowlistStore.shared.remove(id: entry.id)
              await loadEntries()
            }
          }
        }
      }.padding(.vertical, 8)
    }
  }

  private var emptyState: some View {
    VStack(spacing: 12) {
      Image(systemName: "checkmark.circle")
        .font(.system(size: 36)).foregroundColor(.green.opacity(0.5))
      Text("No allowlist entries")
        .font(.system(size: 13)).foregroundColor(.gray)
      Text("Suppress false positives by adding entries")
        .font(.system(size: 11)).foregroundColor(.gray.opacity(0.6))
    }.frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private func loadEntries() async {
    entries = await AllowlistStore.shared.allEntries
  }
}

// MARK: - Entry Row

private struct AllowlistEntryRow: View {
  let entry: AllowlistStore.AllowlistEntry
  let onDelete: () -> Void

  var body: some View {
    HStack(spacing: 10) {
      VStack(alignment: .leading, spacing: 3) {
        Text(entry.reason)
          .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
        HStack(spacing: 8) {
          if let s = entry.scannerId {
            Label(s, systemImage: "magnifyingglass")
              .font(.system(size: 9, design: .monospaced)).foregroundColor(.cyan.opacity(0.7))
          }
          if let p = entry.processName {
            Label(p, systemImage: "gearshape")
              .font(.system(size: 9, design: .monospaced)).foregroundColor(.gray)
          }
          if let t = entry.technique {
            Label(t, systemImage: "exclamationmark.triangle")
              .font(.system(size: 9, design: .monospaced)).foregroundColor(.gray)
          }
        }
        Text(entry.addedAt, style: .relative)
          .font(.system(size: 9)).foregroundColor(.gray.opacity(0.4))
      }
      Spacer()
      Button(action: onDelete) {
        Image(systemName: "trash")
          .font(.system(size: 11)).foregroundColor(.red.opacity(0.6))
      }.buttonStyle(.plain)
    }
    .padding(.horizontal, 20).padding(.vertical, 8)
  }
}

// MARK: - Add Sheet

private struct AddAllowlistSheet: View {
  @Environment(\.dismiss) private var dismiss
  @State private var scannerId = ""
  @State private var processName = ""
  @State private var technique = ""
  @State private var reason = ""
  let onSave: () async -> Void

  var body: some View {
    VStack(spacing: 16) {
      Text("Add Allowlist Entry")
        .font(.system(size: 14, weight: .bold)).foregroundColor(.white)
      Group {
        TextField("Reason (required)", text: $reason)
        TextField("Scanner ID (optional)", text: $scannerId)
        TextField("Process name (optional)", text: $processName)
        TextField("Technique (optional)", text: $technique)
      }
      .textFieldStyle(.roundedBorder)
      .font(.system(size: 12))
      HStack {
        Button("Cancel") { dismiss() }.buttonStyle(.plain)
        Spacer()
        Button("Add") {
          Task {
            await AllowlistStore.shared.add(
              scannerId: scannerId.isEmpty ? nil : scannerId,
              processName: processName.isEmpty ? nil : processName,
              technique: technique.isEmpty ? nil : technique,
              reason: reason)
            await onSave()
            dismiss()
          }
        }
        .disabled(reason.isEmpty)
        .buttonStyle(.borderedProminent)
      }
    }
    .padding(20).frame(width: 360)
  }
}
