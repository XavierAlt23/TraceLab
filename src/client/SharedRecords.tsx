interface SharedRecord {
  id: string; title: string; content: string; revision: number; updated_at: string;
}

export function SharedRecords<T extends SharedRecord>({ records, editable, onEdit }: {
  records: T[]; editable: boolean; onEdit: (record: T) => void;
}) {
  return <section className="shared-records" aria-label="Diez registros compartidos">
    <h2>Registros compartidos</h2>
    <table className="shared-table">
      <caption>Datos ficticios para la exposición. Cada cambio conserva su evidencia.</caption>
      <thead><tr><th scope="col">Título</th><th scope="col">Contenido</th><th scope="col">Revisión</th><th scope="col">Acción</th></tr></thead>
      <tbody>{records.map((record) => <tr key={record.id}>
        <td data-label="Título">{record.title}</td>
        <td data-label="Contenido">{record.content || "Sin contenido"}</td>
        <td data-label="Revisión">{record.revision}<small>Actualizado {new Date(record.updated_at).toLocaleString("es-EC")}</small></td>
        <td data-label="Acción">{editable ? <button className="secondary-button" type="button" onClick={() => onEdit(record)}>EDITAR</button> : "Solo lectura"}</td>
      </tr>)}</tbody>
    </table>
  </section>;
}
