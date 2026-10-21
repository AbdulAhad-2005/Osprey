import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

/** Assistant markdown, themed via .osprey-prose. Links open safely. */
export function Markdown({ children }: { children: string }) {
  return (
    <div className="osprey-prose">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ ...props }) => <a {...props} target="_blank" rel="noopener noreferrer" />,
          pre: ({ children }) => (
            <pre className="my-2.5 overflow-x-auto rounded-lg border border-border bg-abyss p-3 font-mono text-[12.5px] leading-relaxed text-ink-dim">
              {children}
            </pre>
          ),
          code: ({ className, children, ...props }) => {
            const inline = !className;
            return inline ? (
              <code {...props}>{children}</code>
            ) : (
              <code className="text-ink-dim">{children}</code>
            );
          },
          table: ({ children }) => (
            <div className="my-3 overflow-x-auto">
              <table className="w-full border-collapse text-[13px]">{children}</table>
            </div>
          ),
          th: ({ children }) => (
            <th className="border border-border bg-surface-2 px-2.5 py-1.5 text-left font-semibold text-ink">
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="border border-border px-2.5 py-1.5 text-ink-dim">{children}</td>
          ),
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}
