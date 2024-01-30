namespace laujiayuan.viewModels
{
    public class AuditLog
    {
        public int ID { get; set; }
        public string UserId { get; set; }
        public DateTime Timing { get; set; }
        public string Task { get; set; }

    }
}
