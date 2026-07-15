import DOMPurify from "dompurify";

export function Profile({ bio }: { bio: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(bio) }} />;
}

export function render(el: HTMLElement, data: string) {
  el.textContent = data;
}
